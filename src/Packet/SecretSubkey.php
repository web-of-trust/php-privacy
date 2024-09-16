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
    CurveOid,
    DHKeySize,
    KeyAlgorithm,
    RSAKeySize,
    S2kUsage,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    KeyMaterialInterface,
    S2KInterface,
    SubkeyPacketInterface,
};

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
        string $keyData = '',
        ?KeyMaterialInterface $keyMaterial = null,
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?S2KInterface $s2k = null,
        ?AeadAlgorithm $aead = null,
        string $iv = ''
    )
    {
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
        return self::fromSecretKey(SecretKey::fromBytes($bytes));
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
        RSAKeySize $rsaKeySize = RSAKeySize::Normal,
        DHKeySize $dhKeySize = DHKeySize::Normal,
        CurveOid $curveOid = CurveOid::Ed25519,
        ?DateTimeInterface $time = null
    ): self
    {
        return self::fromSecretKey(SecretKey::generate(
            $keyAlgorithm,
            $rsaKeySize,
            $dhKeySize,
            $curveOid,
            $time
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $passphrase,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?AeadAlgorithm $aead = null,
    ): self
    {
        if ($this->getKeyMaterial() instanceof KeyMaterialInterface) {
            $secretKey = parent::encrypt(
                $passphrase, $symmetric, $aead
            );
            return self::fromSecretKey($secretKey);
        }
        else {
            return $this;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $passphrase): self
    {
        if ($this->getKeyMaterial() instanceof KeyMaterialInterface) {
            return $this;
        }
        else {
            return self::fromSecretKey(parent::decrypt($passphrase));
        }
    }

    private static function fromSecretKey(SecretKey $secretKey): self
    {
        $publicKey = $secretKey->getPublicKey();
        return new self(
            new PublicSubkey(
                $publicKey->getVersion(),
                $publicKey->getCreationTime(),
                $publicKey->getKeyAlgorithm(),
                $publicKey->getKeyMaterial(),
            ),
            $secretKey->getKeyData(),
            $secretKey->getKeyMaterial(),
            $secretKey->getS2kUsage(),
            $secretKey->getSymmetric(),
            $secretKey->getS2K(),
            $secretKey->getAead(),
            $secretKey->getIV(),
        );
    }
}
