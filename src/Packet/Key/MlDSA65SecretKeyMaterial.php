<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{EdDSACurve, HashAlgorithm, MlDSA};
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib4\Crypt\EC\Curves\Ed25519;
use PQCrypto\MLDSA65;
use PQCrypto\MLDSA65\SigningKey;

/**
 * Post-quantum ML-DSA-65 secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlDSA65SecretKeyMaterial extends EdDSASecretKeyMaterial
{
    /**
     * PQCrypto ML-DSA-65 decapsulation key
     */
    private readonly SigningKey $signingKey;

    /**
     * Constructor
     *
     * @param string $eccSecret
     * @param KeyMaterialInterface $publicMaterial
     * @param string $mlkemSeed
     * @return self
     */
    public function __construct(
        string $eccSecret,
        KeyMaterialInterface $publicMaterial,
        private readonly string $mlkemSeed,
    ) {
        parent::__construct($eccSecret, $publicMaterial);
        $this->signingKey = SigningKey::fromBytes($mlkemSeed);
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
        return new self(
            substr($bytes, 0, EdDSACurve::Ed25519->payloadSize()),
            $publicMaterial,
            substr($bytes, EdDSACurve::Ed25519->payloadSize()),
        );
    }

    /**
     * Generate key material by using EC create key
     *
     * @param EdDSACurve $curve
     * @return self
     */
    public static function generate(
    ): self {
        $size = EdDSACurve::Ed25519->payloadSize();
        do {
            $privateKey = EC::createKey($curve->name);
            $params = PKCS8::load($privateKey->toString("PKCS8"));
            $secret = $params["secret"];
        } while (strlen($secret) !== $size);

        [$signingKey, $verifyingKey] = MLDSA65::generateKeypair();

        return new self(
            $secret,
            new MlDSA65PublicKeyMaterial(
                $privateKey->getEncodedCoordinates(),
                $verifyingKey->bytes(),
            ),
            $signingKey->bytes(),
        );
    }

    /**
     * Get payload size
     *
     * @return int
     */
    public static function payloadSize(): int
    {
        return EdDSACurve::Ed25519->payloadSize()
            + MlDSA::MlDSA65->secretSize();
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            "eccParameters" => PKCS8::load(
                $this->privateKey->toString("PKCS8")
            ),
            "mlkemSeed" => $this->mlkemSeed,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MlDSA65PublicKeyMaterial) {
            $message = random_bytes(1024);
            $signature = $this->signingKey->sign($message);
            $verifyingKey = $this->publicMaterial->getVerifyingKey();
            $isValid = $verifyingKey->verify($signature, $message);

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
            $this->mlkemSeed,
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
