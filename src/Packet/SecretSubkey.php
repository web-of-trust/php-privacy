<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTimeInterface;
use OpenPGP\Common\{Config, S2K};
use OpenPGP\Enum\{
    CurveOid,
    DHKeySize,
    KeyAlgorithm,
    RSAKeySize,
    S2kUsage,
    SymmetricAlgorithm
};
use OpenPGP\Type\{KeyMaterialInterface, SubkeyPacketInterface};

/**
 * Secret sub key packet class
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
     * @param S2K $s2k
     * @param string $iv
     * @return self
     */
    public function __construct(
        PublicSubkey $publicKey,
        string $keyData = "",
        ?KeyMaterialInterface $keyMaterial = null,
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?S2K $s2k = null,
        string $iv = ""
    ) {
        parent::__construct(
            $publicKey,
            $keyData,
            $keyMaterial,
            $s2kUsage,
            $symmetric,
            $s2k,
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
            $iv
        );
    }

    /**
     * Generate secret subkey packet
     *
     * @param KeyAlgorithm $keyAlgorithm
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curveOid
     * @param DateTimeInterface $time
     * @return self
     */
    public static function generate(
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::S2048,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curveOid = CurveOid::Ed25519,
        ?DateTimeInterface $time = null
    ): self {
        $keyMaterial = self::generateKeyMaterial(
            $keyAlgorithm, $rsaKeySize, $dhKeySize, $curveOid
        );
        return new self(
            new PublicSubkey(
                Config::useV5Key()
                    ? PublicKey::VERSION_5
                    : PublicKey::VERSION_4,
                $time ?? new \DateTime(),
                $keyMaterial->getPublicMaterial(),
                $keyAlgorithm
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
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self {
        if ($this->isDecrypted()) {
            [$encrypted, $iv, $s2k] = $this->encryptKeyMaterial(
                $passphrase,
                $symmetric
            );
            return new self(
                $this->getPublicKey(),
                $encrypted,
                $this->getKeyMaterial(),
                S2kUsage::Sha1,
                $symmetric,
                $s2k,
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
                $this->getIV()
            );
        }
    }
}
