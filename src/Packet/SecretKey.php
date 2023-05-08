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

use OpenPGP\Enum\{KeyAlgorithm, PacketTag, S2kUsage, SymmetricAlgorithm};
use OpenPGP\Packet\Key\{
    KeyParametersInterface,
    RSASecretParameters,
    DSASecretParameters,
    ElGamalSecretParameters,
    ECDHSecretParameters,
    ECDSASecretParameters,
    S2K,
};

/**
 * Secret key packet class
 * 
 * SecretKey represents a possibly encrypted private key.
 * See RFC 4880, section 5.5.3.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SecretKey extends AbstractPacket implements KeyPacketInterface
{
    private KeyParametersInterface? $keyParameters;

    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param S2kUsage $s2kUsage
     * @param SymmetricAlgorithm $symmetric
     * @param S2K $s2k
     * @param string $iv
     * @param string $keyData
     * @param KeyParametersInterface $keyParameters
     * @return self
     */
    public function __construct(
        private PublicKey $publicKey,
        private S2kUsage $s2kUsage = S2kUsage::Sha1,
        private SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        private ?S2K $s2k = null,
        private string $iv = ''
        private string $keyData = '',
        ?KeyParametersInterface $keyParameters = null
    )
    {
        parent::__construct(PacketTag::SecretKey);
        $this->keyParameters = $keyParameters;
    }

    /**
     * Read secret key packets from byte string
     *
     * @param string $bytes
     * @return SecretKey
     */
    public static function fromBytes(string $bytes): SecretKey
    {
        $publicKey = PublicKey::fromBytes($bytes);
        $offset = strlen($publicKey->toBytes());

        $s2kUsage = S2kUsage::from(ord($bytes[$offset++]));

        $s2k = null;
        switch ($s2kUsage) {
            case S2kUsage::Checksum:
            case S2kUsage::Sha1:
                $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));
                $s2k = S2K::fromBytes(substr($bytes, $offset++));
                $offset += $s2k->getLength();
                break;
            default:
                $symmetric = SymmetricAlgorithm::Plaintext;
                break;
        }

        $iv = '';
        if ($s2k instanceof S2K) {
            $iv = substr($bytes, $offset, $symmetric->blockSize());
            $offset += $symmetric->blockSize();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        if ($this->s2kUsage !== S2kUsage::None && $this->s2k instanceof S2K) {
            return implode([
                $this->publicKey->toBytes(),
                chr($this->s2kUsage->value),
                chr($this->symmetric->value),
                $this->s2k->toBytes(),
                $this->iv,
                $this->keyData,
            ]);
        }
        else {
            return implode([
                $this->publicKey->toBytes(),
                chr(S2kUsage::None->value),
                $this->keyData,
            ]);
        }
    }

    private static function readKeyParameters(
        string $bytes, PublicKey $publicKey
    ): KeyParametersInterface
    {
        $keyAlgorithm = $publicKey->getKeyAlgorithm();
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => RSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::RsaEncrypt => RSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::RsaSign => RSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::ElGamal => ElGamalSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::Dsa => DSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::Ecdh => ECDHSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::EcDsa => ECDHSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::EdDsa => ECDHSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
    }
}
