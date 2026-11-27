<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{MlKem, MontgomeryCurve};
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PublicKey;
use PQCrypto\MLKem768\EncapsulationKey;

/**
 * Post-quantum ML-KEM 768 public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlKem768PublicKeyMaterial extends MontgomeryPublicKeyMaterial
{
    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param EncapsulationKey $encapsulationKey
     * @return self
     */
    public function __construct(
        PublicKey $publicKey,
        private readonly EncapsulationKey $encapsulationKey,
    ) {
        parent::__construct($publicKey);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes 
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $publicKey = EC::loadPublicKeyFormat(
            "MontgomeryPublic",
            substr($bytes, 0, MontgomeryCurve::Curve25519->payloadSize()),
        );
        $encapsulationKey = EncapsulationKey::fromBytes(
            substr($bytes, MontgomeryCurve::Curve25519->payloadSize())
        );
        return new self($publicKey, $encapsulationKey);
    }

    /**
     * Get payload size
     *
     * @return int
     */
    public static function payloadSize(): int
    {
        return MontgomeryCurve::Curve25519->payloadSize()
            + MlKem::MlKem768->encapsulationSize();
    }

    /**
     * Get encapsulation key
     *
     * @return EncapsulationKey
     */
    public function getEncapsulationKey(): EncapsulationKey
    {
        return $this->encapsulationKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return MlKem::MlKem768->encapsulationSize() * 8;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            "eccParameters" => parent::getParameters(),
            "mlkemPublic" => $this->encapsulationKey->bytes(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            parent::toBytes(),
            $this->encapsulationKey->bytes(),
        ]);
    }
}
