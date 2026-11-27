<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{EdDSACurve, HashAlgorithm};
use OpenPGP\Type\{
    ECKeyMaterialInterface,
    KeyMaterialInterface,
    SecretKeyMaterialInterface,
};
use phpseclib4\Crypt\Common\{PrivateKey, PublicKey};
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib4\Crypt\EC\Formats\Keys\PKCS8;

/**
 * EdDSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EdDSASecretKeyMaterial implements
    ECKeyMaterialInterface,
    SecretKeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param ECPrivateKey $privateKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        private readonly ECPrivateKey $privateKey,
        private readonly KeyMaterialInterface $publicMaterial,
    ) {
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

        return new self($privateKey, $publicMaterial);
    }

    /**
     * Generate Ed25519 key material by using EC create key
     *
     * @return self
     */
    public static function generateEd25519(): self
    {
        return self::generateEdDSA(EdDSACurve::Ed25519);
    }

    /**
     * Generate Ed448 key material by using EC create key
     *
     * @return self
     */
    public static function generateEd448(): self
    {
        return self::generateEdDSA(EdDSACurve::Ed448);
    }

    private static function generateEdDSA(EdDSACurve $curve): self
    {
        $size = $curve->payloadSize();
        do {
            $privateKey = EC::createKey($curve->name);
            $params = PKCS8::load($privateKey->toString("PKCS8"));
            $secret = $params["secret"];
        } while (strlen($secret) !== $size);
        return new self(
            $privateKey,
            new EdDSAPublicKeyMaterial(
                $privateKey->getPublicKey(),
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getECKey(): EC
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKey
    {
        return $this->privateKey->getPublicKey();
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicMaterial(): KeyMaterialInterface
    {
        return $this->publicMaterial;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return $this->publicMaterial->getKeyLength();
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return PKCS8::load($this->privateKey->toString("PKCS8"));
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof EdDSAPublicKeyMaterial) {
            return hash_equals(
                $this->privateKey->getEncodedCoordinates(),
                $this->publicMaterial->toBytes(),
            );
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        $params = PKCS8::load($this->privateKey->toString("PKCS8"));
        return $params["secret"];
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        return $this->privateKey->sign($hash->hash($message));
    }
}
