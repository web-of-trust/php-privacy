<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{EdDSACurve, HashAlgorithm};
use OpenPGP\Type\MlDSAPublicKeyMaterialInterface;
use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\VerificationKeyInterface;
use ParagonIE\PQCrypto\MLDSA65\VerificationKey as MLDSA65VerificationKey;
use ParagonIE\PQCrypto\MLDSA87\VerificationKey as MLDSA87VerificationKey;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PublicKey;
use phpseclib4\Crypt\EC\Formats\Keys\PKCS8;

/**
 * Post-quantum ML-DSA public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlDSAPublicKeyMaterial extends EdDSAPublicKeyMaterial
    implements MlDSAPublicKeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param VerificationKeyInterface $verificationKey
     * @return self
     */
    public function __construct(
        PublicKey $publicKey,
        private readonly VerificationKeyInterface $verificationKey,
    ) {
        parent::__construct($publicKey);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param EdDSACurve $curve
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        EdDSACurve $curve = EdDSACurve::Ed25519,
    ): self {
        $edCurve = $curve->getCurve();
        $publicKey = EC::loadPublicKeyFormat(
            "PKCS8",
            PKCS8::savePublicKey(
                $edCurve,
                PKCS8::extractPoint(
                    substr($bytes, 0, $curve->payloadSize()), $edCurve
                ),
            ),
        );
        $verificationKey = match ($curve) {
            EdDSACurve::Ed25519 => MLDSA65VerificationKey::fromBytes(
                substr($bytes, $curve->payloadSize())
            ),
            EdDSACurve::Ed448 => MLDSA87VerificationKey::fromBytes(
                substr($bytes, $curve->payloadSize())
            ),
        };
        return new self($publicKey, $verificationKey);
    }

    /**
     * {@inheritdoc}
     */
    public function getVerificationKey(): VerificationKeyInterface
    {
        return $this->verificationKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return strlen($this->verificationKey->bytes()) * 8;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            ...parent::getParameters(),
            "verificationKey" => $this->verificationKey->bytes(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            parent::toBytes(),
            $this->verificationKey->bytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature,
    ): bool {
        // The signature hash algo MUST have digest larger than 256 bits
        // https://www.rfc-editor.org/rfc/rfc9980.html#section-9.4
        if ($hash->digestSize() < 32) {
            throw new \RuntimeException(
                "ML-DSA does not support {$hash->name} hash algorithm.",
            );
        }

        $curveName = $this->getPublicKey()->getCurve();
        $curve = constant(EdDSACurve::class . "::" . $curveName);
        var $eccSignatureSize = $curve->signatureSize();
        $mldsaSignature = match ($curve) {
            EdDSACurve::Ed25519 => substr(
                $signature, $eccSignatureSize, Compat::MLDSA65_SIGNATURE_BYTES
            ),
            EdDSACurve::Ed448 => substr(
                $signature, $eccSignatureSize, Compat::MLDSA87_SIGNATURE_BYTES
            ),
        };
        $isValid = match ($curve) {
            EdDSACurve::Ed25519 => Compat::mldsa65_verify(
                $this->verificationKey, $mldsaSignature, $hash->hash($message)
            ),
            EdDSACurve::Ed448 => Compat::mldsa87_verify(
                $this->verificationKey, $mldsaSignature, $hash->hash($message)
            ),
        };
        var $eccSignature = substr($signature, 0, $eccSignatureSize);

        return $isValid && parent::verify($hash, $hash->hash($message), $eccSignature);
    }
}
