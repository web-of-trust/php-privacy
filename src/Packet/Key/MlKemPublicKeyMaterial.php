<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{MlKemAlgorithm, MontgomeryCurve};
use OpenPGP\Type\MlKemPublicKeyMaterialInterface;
use ParagonIE\PQCrypto\EncapsKeyInterface;
use ParagonIE\PQCrypto\MLKem768\EncapsulationKey as MLKem768EncapsKey;
use ParagonIE\PQCrypto\MLKem1024\EncapsulationKey as MLKem1024EncapsKey;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PublicKey;

/**
 * Post-quantum ML-KEM public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlKemPublicKeyMaterial extends MontgomeryPublicKeyMaterial
    implements MlKemPublicKeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param EncapsKeyInterface $encapsulationKey
     * @return self
     */
    public function __construct(
        PublicKey $publicKey,
        private readonly EncapsKeyInterface $encapsulationKey,
    ) {
        parent::__construct($publicKey);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param MontgomeryCurve $curve
     * @return self
     */
    public static function fromBytes(
        string $bytes, MontgomeryCurve $curve = MontgomeryCurve::Curve25519
    ): self
    {
        $publicKey = EC::loadPublicKeyFormat(
            "MontgomeryPublic",
            substr($bytes, 0, $curve->payloadSize()),
        );
        if ($curve === MontgomeryCurve::Curve25519) {
            $encapsulationKey = new MLKem768EncapsKey(
                substr($bytes, $curve->payloadSize())
            );
        }
        else {
            $encapsulationKey = new MLKem1024EncapsKey(
                substr($bytes, $curve->payloadSize())
            );
        }
        return new self($publicKey, $encapsulationKey);
    }

    /**
     * {@inheritdoc}
     */
    public function getEncapsulationKey(): EncapsKeyInterface
    {
        return $this->encapsulationKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return strlen($this->encapsulationKey->bytes()) * 8;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            ...parent::getParameters(),
            'encapsulationKey' => $this->encapsulationKey->bytes(),
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
