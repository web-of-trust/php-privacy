<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{
    EdDSACurve,
    HashAlgorithm,
};
use OpenPGP\Type\{
    ECKeyMaterialInterface,
    KeyMaterialInterface,
    SecretKeyMaterialInterface,
};
use phpseclib3\Crypt\Common\{
    AsymmetricKey,
    PrivateKey,
    PublicKey,
};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;

/**
 * EdDSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EdDSASecretKeyMaterial implements ECKeyMaterialInterface, SecretKeyMaterialInterface
{
    /**
     * phpseclib3 EC private key
     */
    private readonly ECPrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param string $secret
     * @param KeyMaterialInterface $publicMaterial
     * @param ECPrivateKey $privateKey
     * @return self
     */
    public function __construct(
        private readonly string $secret,
        private readonly KeyMaterialInterface $publicMaterial,
        ?ECPrivateKey $privateKey = null
    )
    {
        if ($privateKey instanceof ECPrivateKey) {
            $this->privateKey = $privateKey;
        }
        else {
            $params = $publicMaterial->getParameters();
            $curve = $params['curve'];
            $arr = $curve->extractSecret($secret);
            $key = PKCS8::savePrivateKey(
                $arr['dA'], $curve, $params['QA'], $arr['secret']
            );
            $this->privateKey = EC::loadPrivateKeyFormat('PKCS8', $key);
        }
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @param EdDSACurve $curve
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        KeyMaterialInterface $publicMaterial,
        EdDSACurve $curve = EdDSACurve::Ed25519
    ): self
    {
        return new self(
            substr($bytes, 0, $curve->payloadSize()),
            $publicMaterial
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
    ): self
    {
        $size = $curve->payloadSize();
        do {
            $privateKey = EC::createKey($curve->name);
            $params = PKCS8::load($privateKey->toString('PKCS8'));
            $secret = $params['secret'];
        } while (strlen($secret) !== $size);
        return new self(
            $secret,
            new EdDSAPublicKeyMaterial(
                $privateKey->getEncodedCoordinates(),
                $params['curve'],
                $privateKey->getPublicKey()
            ),
            $privateKey,
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
    public function getAsymmetricKey(): AsymmetricKey
    {
        return $this->privateKey;
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
        return PKCS8::load($this->privateKey->toString('PKCS8'));
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof EdDSAPublicKeyMaterial) {
            return strcmp(
                $this->privateKey->getEncodedCoordinates(),
                $this->publicMaterial->toBytes(),
            ) === 0;
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->secret;
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        return $this->privateKey->sign(
            $hash->hash($message)
        );
    }
}
