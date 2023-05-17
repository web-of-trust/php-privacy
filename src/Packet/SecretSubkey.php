<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{
    CurveOid,
    DHKeySize,
    HashAlgorithm,
    KeyAlgorithm,
    PacketTag,
    RSAKeySize,
    S2kType,
    S2kUsage,
    SymmetricAlgorithm,
};

/**
 * Secret sub key packet class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SecretSubkey extends SecretKey implements SubkeyPacketInterface
{
    /**
     * Constructor
     *
     * @param PublicSubkey $publicKey
     * @param string $keyData
     * @param Key\KeyParametersInterface $keyParameters
     * @param S2kUsage $s2kUsage
     * @param SymmetricAlgorithm $symmetric
     * @param Key\S2K $s2k
     * @param string $iv
     * @return self
     */
    public function __construct(
        PublicSubkey $publicKey,
        string $keyData = '',
        ?Key\KeyParametersInterface $keyParameters = null,
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?Key\S2K $s2k = null,
        string $iv = ''
    )
    {
        parent::__construct(
        	$publicKey,
            $keyData,
            $keyParameters,
            $s2kUsage,
            $symmetric,
            $s2k,
            $iv
        );
    }

    /**
     * Read secret subkey packets from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return self::fromSecretKey(SecretKey::fromBytes($bytes));
    }

    /**
     * Generate secret subkey packet
     *
     * @param KeyAlgorithm $algorithm
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curveOid
     * @param int $time
     * @return self
     */
    public static function generate(
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::S2048,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curveOid = CurveOid::Secp521r1,
        int $time = 0
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
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        HashAlgorithm $hash = HashAlgorithm::Sha1,
        S2kType $s2kType = S2kType::Iterated
    ): self
    {
        if ($this->getKeyParameters() instanceof Key\KeyParametersInterface) {
            $secretKey = parent::encrypt(
                $passphrase,
                $s2kUsage,
                $symmetric,
                $hash,
                $s2kType
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
        if ($this->getKeyParameters() instanceof Key\KeyParametersInterface) {
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
                $publicKey->getCreationTime(),
                $publicKey->getKeyParameters(),
                $publicKey->getKeyAlgorithm()
            ),
            $secretKey->getKeyData(),
            $secretKey->getKeyParameters(),
            $secretKey->getS2kUsage(),
            $secretKey->getSymmetric(),
            $secretKey->getS2K(),
            $secretKey->getIV()
        );
    }
}
