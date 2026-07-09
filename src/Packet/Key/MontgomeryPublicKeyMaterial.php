<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Type\{ECKeyMaterialInterface, KeyMaterialInterface};
use phpseclib4\Crypt\Common\{AsymmetricKey, PublicKey};
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PublicKey as ECPublicKey;
use phpseclib4\Crypt\EC\Formats\Keys\MontgomeryPublic;

/**
 * Montgomery public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MontgomeryPublicKeyMaterial implements
    ECKeyMaterialInterface,
    KeyMaterialInterface
{
    /**
     * phpseclib4 EC public key
     */
    private readonly ECPublicKey $publicKey;

    /**
     * Constructor
     *
     * @param string $public
     * @return self
     */
    public function __construct(
        private readonly string $public,
    ) {
        $this->publicKey = EC::loadPublicKeyFormat(
            "MontgomeryPublic",
            $public,
        );
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    /**
     * {@inheritdoc}
     */
    public function getECKey(): EC
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return $this->publicKey->getLength();
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicMaterial(): KeyMaterialInterface
    {
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAsymmetricKey(): AsymmetricKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return MontgomeryPublic::load(
            $this->publicKey->toString("MontgomeryPublic"),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->public;
    }
}
