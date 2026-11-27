<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{MlKem, MontgomeryCurve};
use PQCrypto\MLKem1024\EncapsulationKey;

/**
 * Post-quantum ML-KEM 1024 public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlKem1024PublicKeyMaterial extends MontgomeryPublicKeyMaterial
{
    /**
     * PQCrypto ML-KEM 1024 encapsulation key
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
        string $eccPublic,
        private readonly string $mlkemPublic,
    ) {
        parent::__construct($eccPublic);
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
            substr($bytes, 0, MontgomeryCurve::Curve448->payloadSize()),
            substr($bytes, MontgomeryCurve::Curve448->payloadSize()),
        );
    }

    public static function payloadSize(): int
    {
        return MontgomeryCurve::Curve448->payloadSize()
            + MlKem::MlKem1024->encapsulationSize();
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
            'eccParameters' => parent::getParameters(),
            'mlkemPublic' => $this->mlkemPublic,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            parent::toBytes(),
            $this->mlkemPublic,
        ]);
    }
}
