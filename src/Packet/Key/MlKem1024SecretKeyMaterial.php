<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{MlKem, MontgomeryCurve};
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey
use PQCrypto\MLKem1024;
use PQCrypto\MLKem1024\DecapsulationKey;

/**
 * Post-quantum ML-KEM 1024 secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlKem1024SecretKeyMaterial extends MontgomerySecretKeyMaterial
{
    /**
     * Constructor
     *
     * @param PrivateKey $privateKey
     * @param DecapsulationKey $decapsulationKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        PrivateKey $privateKey,
        private readonly DecapsulationKey $decapsulationKey,
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
        $privateKey = EC::loadPrivateKeyFormat(
            "MontgomeryPrivate",
            substr($bytes, 0, MontgomeryCurve::Curve448->payloadSize()),
        );
        $decapsulationKey = DecapsulationKey::fromBytes(
            substr($bytes, MontgomeryCurve::Curve448->payloadSize())
        );
        return new self(
            $privateKey,
            $decapsulationKey,
            $publicMaterial,
        );
    }

    /**
     * Generate ML-KEM 1024 key material
     *
     * @return self
     */
    public static function generate(): self {
        [$sk, $pk] = MLKem1024::generateKeypair();
        $eccKey = EC::loadPrivateKeyFormat(
            "MontgomeryPrivate", MontgomeryCurve::Curve448->generateSecretKey()
        );
        return new self(
            $eccKey,
            $sk,
            new MlKem1024PublicKeyMaterial(
                $eccKey->getPublicKey(),
                $pk,
            ),
        );
    }

    /**
     * Get payload size
     *
     * @return int
     */
    public static function payloadSize(): int
    {
        return MontgomeryCurve::Curve448->payloadSize()
            + MlKem::MlKem1024->decapsulationSize();
    }

    /**
     * Get decapsulation key
     *
     * @return DecapsulationKey
     */
    public function getDecapsulationKey(): DecapsulationKey
    {
        return $this->decapsulationKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            'eccParameters' => parent::getParameters(),
            'mlkemSeed' => $this->mlkemSeed,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MlKem1024PublicKeyMaterial) {
            $encapsKey = $this->publicMaterial->getEncapsulationKey();
            [$sharedSecret, $ciphertext] = $encapsKey->encapsulate();
            $recipientSecret = $this->decapsulationKey->decapsulate($ciphertext);
            $isValid = hash_equals($recipientSecret, $sharedSecret);

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
            $this->mlkemSeed,
        ]);
    }
}
