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
use phpseclib4\Crypt\Common\{PrivateKey, PublicKey};
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib4\Crypt\EC\Formats\Keys\MontgomeryPrivate;

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
        $privateKey = EC::loadPrivateKeyFormat(
            "MontgomeryPrivate",
            $bytes,
        );
        return new self($privateKey,$publicMaterial);
    }

    /**
     * Generate Montgomery key material
     *
     * @param MontgomeryCurve $curve
     * @return self
     */
    public static function generate(
        MontgomeryCurve $curve = MontgomeryCurve::Curve25519,
    ): self {
        $privateKey = EC::loadPrivateKeyFormat(
            "MontgomeryPrivate", $curve->generateSecretKey()
        );
        return new self(
            $privateKey,
            new MontgomeryPublicKeyMaterial(
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
        return MontgomeryPrivate::load(
            $this->privateKey->toString("MontgomeryPrivate"),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MontgomeryPublicKeyMaterial) {
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
        return $this->privateKey->toString("MontgomeryPrivate");
    }
}
