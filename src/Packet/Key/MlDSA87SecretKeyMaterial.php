<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{EdDSACurve, HashAlgorithm, MlDsaAlgorithm};
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey;
use phpseclib4\Crypt\EC\Formats\Keys\PKCS8;
use PQCrypto\MLDSA87;
use PQCrypto\MLDSA87\SigningKey;

/**
 * Post-quantum ML-DSA-87 secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlDSA87SecretKeyMaterial extends EdDSASecretKeyMaterial
{
    /**
     * Constructor
     *
     * @param PrivateKey $privateKey
     * @param SigningKey $signingKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        PrivateKey $privateKey,
        private readonly SigningKey $signingKey,
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
        $signingKey = SigningKey::fromBytes(
            substr($bytes, EdDSACurve::Ed448->payloadSize())
        );
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
    public static function generate(): self
    {
        $size = EdDSACurve::Ed448->payloadSize();
        do {
            $privateKey = EC::createKey($curve->name);
            $params = PKCS8::load($privateKey->toString("PKCS8"));
            $secret = $params["secret"];
        } while (strlen($secret) !== $size);

        [$signingKey, $verifyingKey] = MLDSA87::generateKeypair();

        return new self(
            $secret,
            new MlDSA87PublicKeyMaterial(
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
        return EdDSACurve::Ed448->payloadSize()
            + MlDsaAlgorithm::MlDSA87->secretSize();
    }

    /**
     * Get signing key
     *
     * @return SigningKey
     */
    public function getSigningKey(): SigningKey
    {
        return $this->signingKey;
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
            "mlkemSeed" => $this->signingKey->bytes(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MlDSA87PublicKeyMaterial) {
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
            $this->signingKey->bytes(),
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
