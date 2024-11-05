<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTimeInterface;
use OpenPGP\Common\Config;
use OpenPGP\Enum\{
    AeadAlgorithm,
    Ecc,
    KeyAlgorithm,
    RSAKeySize,
    S2kUsage,
    SymmetricAlgorithm
};
use OpenPGP\Type\{KeyMaterialInterface, S2KInterface, SubkeyPacketInterface};

/**
 * Implementation a possibly encrypted sub private key (Tag 7).
 *
 * See RFC 9580, section 5.5.1.4.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SecretSubkey extends SecretKey implements SubkeyPacketInterface
{
    /**
     * Constructor
     *
     * @param PublicSubkey $publicKey
     * @param string $keyData
     * @param KeyMaterialInterface $keyMaterial
     * @param S2kUsage $s2kUsage
     * @param SymmetricAlgorithm $symmetric
     * @param S2KInterface $s2k
     * @param AeadAlgorithm $aead
     * @param string $iv
     * @return self
     */
    public function __construct(
        PublicSubkey $publicKey,
        string $keyData = "",
        ?KeyMaterialInterface $keyMaterial = null,
        S2kUsage $s2kUsage = S2kUsage::None,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?S2KInterface $s2k = null,
        ?AeadAlgorithm $aead = null,
        string $iv = ""
    ) {
        parent::__construct(
            $publicKey,
            $keyData,
            $keyMaterial,
            $s2kUsage,
            $symmetric,
            $s2k,
            $aead,
            $iv
        );
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $publicKey = PublicSubkey::fromBytes($bytes);
        [
            $s2kUsage,
            $symmetric,
            $aead,
            $s2k,
            $iv,
            $keyData,
            $keyMaterial,
        ] = self::decode($bytes, $publicKey);
        return new self(
            $publicKey,
            $keyData,
            $keyMaterial,
            $s2kUsage,
            $symmetric,
            $s2k,
            $aead,
            $iv
        );
    }

    /**
     * Generate secret subkey packet
     *
     * @param KeyAlgorithm $keyAlgorithm
     * @param RSAKeySize $rsaKeySize
     * @param Ecc $curve
     * @param DateTimeInterface $time
     * @return self
     */
    public static function generate(
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::Normal,
        Ecc $curve = Ecc::Ed25519,
        ?DateTimeInterface $time = null
    ): self {
        $keyMaterial = self::generateKeyMaterial(
            $keyAlgorithm, $rsaKeySize, $curve
        );
        $version = match ($keyAlgorithm) {
            KeyAlgorithm::X25519,
            KeyAlgorithm::X448,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::Ed448
                => PublicKey::VERSION_6,
            default => Config::useV6Key()
                ? PublicKey::VERSION_6
                : PublicKey::VERSION_4,
        };
        return new self(
            new PublicSubkey(
                $version,
                $time ?? new \DateTime(),
                $keyAlgorithm,
                $keyMaterial->getPublicMaterial()
            ),
            $keyMaterial->toBytes(),
            $keyMaterial
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $passphrase,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?AeadAlgorithm $aead = null
    ): self {
        if ($this->isDecrypted()) {
            [$encrypted, $iv, $s2k] = parent::encryptKeyMaterial($passphrase, $symmetric, $aead);
            return new self(
                $this->getPublicKey(),
                $encrypted,
                $this->getKeyMaterial(),
                $aead instanceof AeadAlgorithm ? S2kUsage::AeadProtect : S2kUsage::Cfb,
                $symmetric,
                $s2k,
                $aead,
                $iv
            );
        } else {
            return $this;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $passphrase): self
    {
        if ($this->isDecrypted()) {
            return $this;
        } else {
            return new self(
                $this->getPublicKey(),
                $this->getKeyData(),
                $this->decryptKeyData($passphrase),
                $this->getS2kUsage(),
                $this->getSymmetric(),
                $this->getS2K(),
                $this->getAead(),
                $this->getIV()
            );
        }
    }
}
