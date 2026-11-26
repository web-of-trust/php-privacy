<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{MlKem, MontgomeryCurve};
use OpenPGP\Type\{ECKeyMaterialInterface, KeyMaterialInterface};
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PublicKey as ECPublicKey;
use phpseclib4\Crypt\EC\Formats\Keys\MontgomeryPublic;
use PQCrypto\MLKem768\EncapsulationKey;

/**
 * Post-quantum ML-KEM 768 public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlKem768PublicKeyMaterial implements
    ECKeyMaterialInterface,
    KeyMaterialInterface
{
    /**
     * phpseclib4 EC public key
     */
    private readonly ECPublicKey $publicKey;

    /**
     * PQCrypto MLKem768 encapsulation key
     */
    private readonly EncapsulationKey $encapsulationKey;

    /**
     * Constructor
     *
     * @param string $eccPublic
     * @param string $mlkemPublic
     * @return self
     */
    public function __construct(
        private readonly string $eccPublic,
        private readonly string $mlkemPublic,
    ) {
        $this->publicKey = EC::loadPublicKeyFormat(
            "MontgomeryPublic",
            $eccPublic,
        );
        $this->encapsulationKey = EncapsulationKey::fromBytes($mlkemPublic);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes 
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return new self(
            substr($bytes, 0, MontgomeryCurve::Curve25519->payloadSize()),
            substr($bytes, MontgomeryCurve::Curve25519->payloadSize()),
        );
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
    public function getECKey(): EC
    {
        return MlKem::MlKem768->encapsulationSize();
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
        return [
            'eccPublic' => $this->eccPublic,
            'mlkemPublic' => $this->mlkemPublic,
        ];
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
        return implode($this->getParameters());
    }
}
