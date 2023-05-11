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
    HashAlgorithm, PacketTag, S2kType, S2kUsage, SymmetricAlgorithm
};
use OpenPGP\Packet\Key\{KeyParametersInterface, S2K};

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
     * @param S2kUsage $s2kUsage
     * @param SymmetricAlgorithm $symmetric
     * @param S2K $s2k
     * @param string $iv
     * @param string $keyData
     * @param KeyParametersInterface $keyParameters
     * @return self
     */
    public function __construct(
        PublicSubkey $publicKey,
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?S2K $s2k = null,
        string $iv = '',
        string $keyData = '',
        ?KeyParametersInterface $keyParameters = null
    )
    {
        parent::__construct(
        	$publicKey, $s2kUsage, $symmetric, $s2k, $iv, $keyData, $keyParameters
        );
        $this->setTag(PacketTag::SecretSubkey);
    }

    /**
     * Read secret subkey packets from byte string
     *
     * @param string $bytes
     * @return SecretKeyPacketInterface
     */
    public static function fromBytes(string $bytes): SecretKeyPacketInterface
    {
        return self::fromSecretKey(SecretKey::fromBytes($bytes));
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
    ): SecretKeyPacketInterface
    {
        if ($this->getKeyParameters() instanceof KeyParametersInterface ) {
            $secretKey = parent::encrypt(
                $passphrase, $s2kUsage, $symmetric, $hash, $s2kType
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
    public function decrypt(string $passphrase): SecretKeyPacketInterface
    {
        if ($this->getKeyParameters() instanceof KeyParametersInterface ) {
            return $this;
        }
        else {
            return self::fromSecretKey(parent::decrypt($passphrase));
        }
    }

    private static function fromSecretKey(SecretKey $secretKey): SecretKeyPacketInterface
    {
        $publicKey = $secretKey->getPublicKey();
        return new SecretSubkey(
            new PublicSubkey(
                $publicKey->getCreationTime(),
                $publicKey->getKeyParameters(),
                $publicKey->getKeyAlgorithm(),
            ),
            $secretKey->getS2kUsage(),
            $secretKey->getSymmetric(),
            $secretKey->getS2K(),
            $secretKey->getIV(),
            $secretKey->getKeyData(),
            $secretKey->getKeyParameters()
        );
    }
}
