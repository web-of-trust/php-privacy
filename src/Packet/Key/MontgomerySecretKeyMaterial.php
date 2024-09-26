<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\MontgomeryCurve;
use OpenPGP\Type\{ECKeyMaterialInterface, KeyMaterialInterface};
use phpseclib3\Crypt\Common\{AsymmetricKey, PrivateKey, PublicKey};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\MontgomeryPrivate;

/**
 * Montgomery secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MontgomerySecretKeyMaterial implements
    ECKeyMaterialInterface,
    KeyMaterialInterface
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
    ) {
        if ($privateKey instanceof ECPrivateKey) {
            $this->privateKey = $privateKey;
        } else {
            $this->privateKey = EC::loadPrivateKeyFormat(
                "MontgomeryPrivate",
                $secret
            );
        }
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
        MontgomeryCurve $curve = MontgomeryCurve::Curve25519
    ): self {
        return new self(
            substr($bytes, 0, $curve->payloadSize()),
            $publicMaterial
        );
    }

    /**
     * Generate Montgomery key material
     *
     * @param MontgomeryCurve $curve
     * @return self
     */
    public static function generate(
        MontgomeryCurve $curve = MontgomeryCurve::Curve25519
    ): self {
        $size = $curve->payloadSize();
        do {
            $privateKey = EC::createKey($curve->name);
            $secret = $privateKey->toString("MontgomeryPrivate");
        } while (strlen($secret) !== $size);
        return new self(
            $secret,
            new MontgomeryPublicKeyMaterial(
                $privateKey->getEncodedCoordinates(),
                $privateKey->getPublicKey()
            ),
            $privateKey
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
        return MontgomeryPrivate::load(
            $this->privateKey->toString("MontgomeryPrivate")
        );
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MontgomeryPublicKeyMaterial) {
            return strcmp(
                $this->privateKey->getEncodedCoordinates(),
                $this->publicMaterial->toBytes()
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
}
