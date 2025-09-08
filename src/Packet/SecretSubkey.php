<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTimeInterface;
use OpenPGP\Enum\{
    AeadAlgorithm,
    Ecc,
    KeyAlgorithm,
    RSAKeySize,
    S2kUsage,
    SymmetricAlgorithm,
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
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        ?S2KInterface $s2k = null,
        ?AeadAlgorithm $aead = null,
        string $iv = "",
    ) {
        parent::__construct(
            $publicKey,
            $keyData,
            $keyMaterial,
            $s2kUsage,
            $symmetric,
            $s2k,
            $aead,
            $iv,
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
            $iv,
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
        Ecc $curve = Ecc::Secp521r1,
        ?DateTimeInterface $time = null,
    ): self {
        $keyMaterial = self::generateKeyMaterial(
            $keyAlgorithm,
            $rsaKeySize,
            $curve,
        );
        return new self(
            new PublicSubkey(
                $keyAlgorithm->keyVersion(),
                $time ?? new \DateTime(),
                $keyAlgorithm,
                $keyMaterial->getPublicMaterial(),
            ),
            $keyMaterial->toBytes(),
            $keyMaterial,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $passphrase,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        ?AeadAlgorithm $aead = null,
    ): self {
        if ($this->isDecrypted()) {
            [$encrypted, $iv, $s2k] = $this->encryptKeyMaterial(
                $passphrase,
                $symmetric,
                $aead,
            );
            return new self(
                $this->getPublicKey(),
                $encrypted,
                $this->getKeyMaterial(),
                $aead instanceof AeadAlgorithm
                    ? S2kUsage::AeadProtect
                    : S2kUsage::Cfb,
                $symmetric,
                $s2k,
                $aead,
                $iv,
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
                $this->getIV(),
            );
        }
    }
}
