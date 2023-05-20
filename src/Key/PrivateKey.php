<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTime;
use OpenPGP\Common\Armor;
use OpenPGP\Enum\{
    ArmorType,
    DHKeySize,
    KeyAlgorithm,
    KeyType,
    PacketTag,
    RSAKeySize
};
use OpenPGP\Packet\{
    PacketList,
    SecretKey,
    SecretSubkey,
    Signature,
    UserID
};
use OpenPGP\Type\{
    KeyInterface,
    PacketListInterface,
    SecretKeyPacketInterface
};

/**
 * OpenPGP private key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PrivateKey extends AbstractKey
{
    /**
     * Reads private key from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::PrivateKey) {
            throw new \UnexpectedValueException(
                'Armored text not of private key type'
            );
        }
        return self::fromPacketList(
            PacketList::decode($armor->getData())
        );
    }

    /**
     * Reads private key from packet list
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function fromPacketList(PacketListInterface $packetList): self
    {
        $keyMap = self::readPacketList($packetList);
        if (!($keyMap['keyPacket'] instanceof SecretKeyPacketInterface)) {
            throw new \UnexpectedValueException(
                'Key packet is not secret key type'
            );
        }
        $privateKey = new self(
            $keyMap['keyPacket'],
            $keyMap['revocationSignatures'],
            $keyMap['directSignatures']
        );
        $users = array_map(
            static fn ($user) => new User(
                $privateKey,
                $user['userIDPacket'],
                $user['revocationSignatures'],
                $user['selfCertifications'],
                $user['otherCertifications']
            ),
            $keyMap['users']
        );
        $privateKey->setUsers($users);
        $subkeys = array_map(
            static fn ($subkey) => new Subkey(
                $privateKey,
                $subkey['keyPacket'],
                $subkey['revocationSignatures'],
                $subkey['bindingSignatures']
            ),
            $keyMap['subkeys']
        );
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }

    /**
     * Generates a new OpenPGP key pair. Supports RSA and ECC keys.
     * By default, primary and subkeys will be of same type.
     * The generated primary key will have signing capabilities.
     * By default, one subkey with encryption capabilities is also generated.
     *
     * @param array $userIDs
     * @param string $passphrase
     * @param KeyType $type
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curve
     * @param CurveOid $keyExpiry
     * @param DateTime $date
     * @return self
     */
    public static function generate(
        array $userIDs,
        string $passphrase,
        KeyType $type = KeyType::Rsa,
        RSAKeySize $rsaKeySize = RSAKeySize::S4096,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        ?DateTime $date = null
    ): self
    {
        if (empty($userIDs) || empty($passphrase)) {
            throw new \InvalidArgumentException(
                'UserIDs and passphrase are required for key generation',
            );
        }
        $keyAlgorithm = KeyAlgorithm::RsaEncryptSign;
        $subkeyAlgorithm = KeyAlgorithm::RsaEncryptSign;
        if ($type = KeyType::Dsa) {
            $keyAlgorithm = KeyAlgorithm::Dsa;
            $subkeyAlgorithm = KeyAlgorithm::ElGamal;
        }
        elseif ($type = KeyType::Ecc) {
            if ($curve == CurveOid::Ed25519 || $curve == CurveOid::Curve25519) {
                $keyAlgorithm = KeyAlgorithm::EdDsa;
            }
            else {
                $keyAlgorithm = KeyAlgorithm::EcDsa;
            }
            $subkeyAlgorithm = KeyAlgorithm::Ecdh;
        }

        $secretKey = SecretKey::generate(
            $keyAlgorithm,
            $rsaKeySize,
            $dhKeySize,
            $curve,
            $date,
        )->encrypt($passphrase);
        $secretSubkey = SecretSubkey::generate(
            $subkeyAlgorithm,
            $rsaKeySize,
            $dhKeySize,
            $curve,
            $date,
        )->encrypt($passphrase);

        $packets = [$secretKey];

        // Wrap user id with certificate signature
        foreach ($userIDs as $userID) {
            $packet = new UserID($userID);
            $packets[] = $packet;
            $packets[] = Signature::createCertGeneric(
                $secretKey, $packet, $date
            );
        }

        // Wrap secret subkey with binding signature
        $packets[] = $secretSubkey;
        $packets[] = Signature::createSubkeyBinding(
            $secretKey, $secretSubkey, $keyExpiry, $date
        );

        return self::fromPacketList((new PacketList($packets)));
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::PrivateKey,
            $this->toPacketList()->encode()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toPublic(): KeyInterface
    {
        $packets = [];
        foreach ($this->toPacketList()->toArray() as $packet) {
            switch ($packet->getTag()) {
                case PacketTag::SecretKey:
                case PacketTag::SecretSubkey:
                    $packets[] = $packet->getPublicKey();
                    break;
                default:
                    $packets[] = $packet;
                    break;
            }
        }
        return PublicKey::fromPacketList((new PacketList($packets)));
    }

    /**
     * Returns true if the key packet is encrypted.
     * 
     * @return bool
     */
    public function isEncrypted(): bool
    {
        return $this->getKeyPacket()->isEncrypted();
    }

    /**
     * Returns true if the key packet is decrypted.
     * 
     * @return bool
     */
    public function isDecrypted(): bool
    {
        return $this->getKeyPacket()->isDecrypted();
    }

    /**
     * Lock a private key with the given passphrase.
     * This method does not change the original key.
     * 
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @return self
     */
    public function encrypt(
        string $passphrase,
        array $subkeyPassphrases = []
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'passphrase are required for key encryption'
            );
        }
        $privateKey = new self(
            $this->getKeyPacket()->encrypt($passphrase),
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
        );

        $users = array_map(
            static fn ($user) => new User(
                $privateKey,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications()
            ),
            $this->getUsers()
        );
        $privateKey->setUsers($users);

        $subkeys = [];
        foreach ($this->getSubkeys() as $key => $subkey) {
            $subkeyPassphrase = isset($subkeyPassphrases[$key]) ? $subkeyPassphrases[$key] : $passphrase;
            $keyPacket = $subkey->getKeyPacket()->encrypt($subkeyPassphrase);
            $subkeys[] = new Subkey(
                $privateKey,
                $keyPacket,
                $subkey->getRevocationSignatures(),
                $subkey->getRevocationSignatures()
            );
        }
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }

    /**
     * Unlock a private key with the given passphrase.
     * This method does not change the original key.
     * 
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @return self
     */
    public function decrypt(
        string $passphrase, array $subkeyPassphrases = []
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'passphrase are required for key decryption'
            );
        }
        $secretKey = $this->getKeyPacket()->decrypt($passphrase);
        if (!$secretKey->getKeyParameters()->isValid()) {
            throw new \UnexpectedValueException(
                'The key parameters are not consistent'
            );
        }
        $privateKey = new self(
            $secretKey,
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
        );

        $users = array_map(
            static fn ($user) => new User(
                $privateKey,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications()
            ),
            $this->getUsers()
        );
        $privateKey->setUsers($users);

        $subkeys = [];
        foreach ($this->getSubkeys() as $key => $subkey) {
            $subkeyPassphrase = isset($subkeyPassphrases[$key]) ? $subkeyPassphrases[$key] : $passphrase;
            $keyPacket = $subkey->getKeyPacket()->decrypt($subkeyPassphrase);
            $subkeys[] = new Subkey(
                $privateKey,
                $keyPacket,
                $subkey->getRevocationSignatures(),
                $subkey->getRevocationSignatures()
            );
        }
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }
}
