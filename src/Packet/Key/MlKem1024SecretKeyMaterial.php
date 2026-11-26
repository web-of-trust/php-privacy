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
use phpseclib4\Crypt\Common\{AsymmetricKey, PrivateKey, PublicKey};
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib4\Crypt\EC\Formats\Keys\MontgomeryPrivate;
use PQCrypto\MLKem1024;
use PQCrypto\MLKem1024\DecapsulationKey;

/**
 * Post-quantum ML-KEM 1024 secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlKem1024SecretKeyMaterial implements
    ECKeyMaterialInterface,
    KeyMaterialInterface
{
    /**
     * phpseclib4 EC private key
     */
    private readonly ECPrivateKey $privateKey;

    /**
     * PQCrypto MLKem1024 MLKem1024 decapsulation key
     */
    private readonly DecapsulationKey $decapsulationKey;

    /**
     * Constructor
     *
     * @param string $eccSecret
     * @param string $mlkemSeed
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        private readonly string $eccSecret,
        private readonly string $mlkemSeed,
        private readonly KeyMaterialInterface $publicMaterial,
    ) {
        $this->privateKey = EC::loadPrivateKeyFormat(
            "MontgomeryPrivate",
            $eccSecret,
        );
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
            substr($bytes, MontgomeryCurve::Curve448->payloadSize()),
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
        return [
            'eccSecret' => $this->eccSecret,
            'mlkemSeed' => $this->mlkemSeed,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MlKem1024PublicKeyMaterial) {
            $publicParams = $this->publicMaterial->getParameters();
            $eccValid = hash_equals(
                $this->privateKey->getEncodedCoordinates(),
                $publicParams['eccPublic'],
            );

            $encapsKey = $this->publicMaterial->getEncapsulationKey();
            [$sharedSecret, $ciphertext] = $encapsKey->encapsulate();
            $recipientSecret = $this->decapsulationKey->decapsulate($ciphertext);

            $mlkemValid = hash_equals($recipientSecret, $sharedSecret);
            return $eccValid && $mlkemValid;
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode($this->getParameters());
    }
}
