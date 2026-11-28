<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{EdDSACurve, HashAlgorithm, MlDsaAlgorithm};
use OpenPGP\Type\{KeyMaterialInterface, MlDSASecretKeyMaterialInterface};
use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\{SigningKeyInterface, VerificationKeyInterface};
use ParagonIE\PQCrypto\MLDSA65\SigningKey as MLDSA65SigningKey;
use ParagonIE\PQCrypto\MLDSA87\SigningKey as MLDSA87SigningKey;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey;
use phpseclib4\Crypt\EC\Formats\Keys\PKCS8;

/**
 * Post-quantum ML-DSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlDSASecretKeyMaterial extends EdDSASecretKeyMaterial
    implements MlDSASecretKeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param PrivateKey $privateKey
     * @param SigningKeyInterface $signingKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        PrivateKey $privateKey,
        private readonly SigningKeyInterface $signingKey,
        KeyMaterialInterface $publicMaterial,
    ) {
        parent::__construct($privateKey, $publicMaterial);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        KeyMaterialInterface $publicMaterial,
    ): self {
        $params = $publicMaterial->getParameters();
        $curve = $params["curve"];
        $arr = $curve->extractSecret(substr($bytes, 0, $curve::SIZE));
        $privateKey = EC::loadPrivateKeyFormat(
            "PKCS8",
            PKCS8::savePrivateKey(
                $arr["dA"],
                $curve,
                $params["QA"],
                $arr["secret"],
            ),
        );
        if ($curve::SIZE === EdDSACurve::Ed25519->payloadSize()) {
            $signingKey = MLDSA65SigningKey::fromBytes(
                substr($bytes, $curve::SIZE)
            );
        }
        else {
            $signingKey = MLDSA87SigningKey::fromBytes(
                substr($bytes, $curve::SIZE)
            );
        }
        return new self(
            $privateKey, $signingKey, $publicMaterial,
        );
    }

    /**
     * Generate key material by using EC create key
     *
     * @param EdDSACurve $curve
     * @return self
     */
    public static function generate(
        EdDSACurve $curve = EdDSACurve::Ed25519
    ): self {
        $size = $curve->payloadSize();
        do {
            $privateKey = EC::createKey($curve->name);
            $params = PKCS8::load($privateKey->toString("PKCS8"));
            $secret = $params["secret"];
        } while (strlen($secret) !== $size);

        if ($curve === EdDSACurve::Ed25519) {
            ['signingKey' => $sk, 'verificationKey' => $vk] = Compat::mldsa65_keygen();
        }
        else {
            ['signingKey' => $sk, 'verificationKey' => $vk] = Compat::mldsa87_keygen();
        }

        return new self(
            $privateKey,
            $sk,
            new MlDSAPublicKeyMaterial(
                $privateKey->getPublicKey(),
                $vk,
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSigningKey(): SigningKeyInterface
    {
        return $this->signingKey;
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
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MlDSAPublicKeyMaterial) {
            $curve = $this->publicMaterial->getPublicKey()->getCurve();
            $verificationKey = $this->publicMaterial->getVerificationKey();

            $message = random_bytes(1024);
            if ($curve === EdDSACurve::Ed25519->name) {
                $signature = Compat::mldsa65_sign($this->signingKey, $message);
                $isValid = Compat::mldsa65_verify($verificationKey, $signature, $message);
            }
            else {
                $signature = Compat::mldsa87_sign($this->signingKey, $message);
                $isValid = Compat::mldsa87_verify($verificationKey, $signature, $message);
            }

            return $isValid && parent::isValid();
        }
        return false;
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
    public function sign(HashAlgorithm $hash, string $message): string
    {
        return "";
    }
}
