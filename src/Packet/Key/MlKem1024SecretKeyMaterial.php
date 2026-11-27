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
     * PQCrypto ML-KEM 1024 decapsulation key
     */
    private readonly DecapsulationKey $decapsulationKey;

    /**
     * Constructor
     *
     * @param string $eccSecret
     * @param KeyMaterialInterface $publicMaterial
     * @param string $mlkemSeed
     * @return self
     */
    public function __construct(
        string $eccSecret,
        KeyMaterialInterface $publicMaterial,
        private readonly string $mlkemSeed,
    ) {
        parent::__construct($eccSecret, $publicMaterial);
        $this->decapsulationKey = DecapsulationKey::fromBytes($mlkemSeed);
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
        return new self(
            substr($bytes, 0, MontgomeryCurve::Curve448->payloadSize()),
            $publicMaterial,
            substr($bytes, MontgomeryCurve::Curve448->payloadSize()),
        );
    }

    /**
     * Generate ML-KEM 1024 key material
     *
     * @return self
     */
    public static function generate(): self {
        [$sk, $pk] = MLKem1024::generateKeypair();
        $secret = MontgomeryCurve::Curve448->generateSecretKey();
        $eccKey = EC::loadPrivateKeyFormat("MontgomeryPrivate", $secret);
        return new self(
            $secret,
            $sk->bytes(),
            new MlKem1024PublicKeyMaterial(
                $eccKey->getEncodedCoordinates(),
                $pk->bytes(),
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
            $mlkemValid = hash_equals($recipientSecret, $sharedSecret);

            return parent::isValid() && $mlkemValid;
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
