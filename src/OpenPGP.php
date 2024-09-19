<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP;

/**
 * OpenPGP class
 * Export high level API for developers.
 *
 * @package OpenPGP
 * @author  Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class OpenPGP
{
    /**
     * Generate a new OpenPGP key pair. Support RSA, DSA, ECC, Curve25519 and Curve448 key types.
     * The generated primary key will have signing capabilities.
     * One subkey with encryption capabilities is also generated.
     *
     * @param array $userIDs
     * @param string $passphrase
     * @param Enum\KeyType $type
     * @param Enum\RSAKeySize $rsaKeySize
     * @param Enum\DHKeySize $dhKeySize
     * @param Enum\CurveOid $curve
     * @param int $keyExpiry
     * @param \DateTimeInterface $time
     * @return Type\PrivateKeyInterface
     */
    public static function generateKey(
        array $userIDs,
        string $passphrase,
        Enum\KeyType $type = Enum\KeyType::Rsa,
        Enum\RSAKeySize $rsaKeySize = Enum\RSAKeySize::Normal,
        Enum\DHKeySize $dhKeySize = Enum\DHKeySize::Normal,
        Enum\CurveOid $curve = Enum\CurveOid::Secp521r1,
        int $keyExpiry = 0,
        ?\DateTimeInterface $time = null
    ): Type\PrivateKeyInterface
    {
        return Key\PrivateKey::generate(
            $userIDs,
            $passphrase,
            $type,
            $rsaKeySize,
            $dhKeySize,
            $curve,
            $keyExpiry,
            $time,
        );
    }

    /**
     * Read OpenPGP private key from armored/binary string.
     * Return a private key object.
     *
     * @param string $privateKey
     * @param bool $armored
     * @return Type\PrivateKeyInterface
     */
    public static function readPrivateKey(
        string $privateKey, bool $armored = true
    ): Type\PrivateKeyInterface
    {
        return $armored ?
            Key\PrivateKey::fromArmored($privateKey) :
            Key\PrivateKey::fromBytes($privateKey);
    }

    /**
     * Read OpenPGP public key from armored/binary string.
     * Return a public key object.
     *
     * @param string $publicKey
     * @param bool $armored
     * @return Type\KeyInterface
     */
    public static function readPublicKey(
        string $publicKey, bool $armored = true
    ): Type\KeyInterface
    {
        return $armored ?
            Key\PublicKey::fromArmored($publicKey) :
            Key\PublicKey::fromBytes($publicKey);
    }

    /**
     * Read OpenPGP public key list from armored/binary string.
     * Return array of public key objects.
     *
     * @param string $publicKeys
     * @param bool $armored
     * @return array
     */
    public static function readPublicKeys(
        string $publicKeys, bool $armored = true
    ): array
    {
        return Key\PublicKey::readPublicKeys($publicKeys, $armored);
    }

    /**
     * Lock a private key with the given passphrase.
     * The private key must be decrypted.
     *
     * @param Type\PrivateKeyInterface $privateKey
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @return Type\PrivateKeyInterface
     */
    public static function encryptPrivateKey(
        Type\PrivateKeyInterface $privateKey,
        string $passphrase,
        array $subkeyPassphrases = []
    ): Type\PrivateKeyInterface
    {
        return $privateKey->encrypt(
            $passphrase, $subkeyPassphrases
        );
    }

    /**
     * Read & unlock OpenPGP private key with the given passphrase.
     *
     * @param string $privateKey
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @param bool $armored
     * @return Type\PrivateKeyInterface
     */
    public static function decryptPrivateKey(
        string $privateKey,
        string $passphrase,
        array $subkeyPassphrases = [],
        bool $armored = true
    ): Type\PrivateKeyInterface
    {
        return self::readPrivateKey($privateKey, $armored)->decrypt(
            $passphrase, $subkeyPassphrases
        );
    }

    /**
     * Certify an OpenPGP key by a private key.
     * Return clone of the key object with the new certification added.
     *
     * @param Type\PrivateKeyInterface $privateKey
     * @param Type\KeyInterface $key
     * @param \DateTimeInterface $time
     * @return Type\KeyInterface
     */
    public static function certifyKey(
        Type\PrivateKeyInterface $privateKey,
        Type\KeyInterface $key,
        ?\DateTimeInterface $time = null
    ): Type\KeyInterface
    {
        return $privateKey->certifyKey($key, $time);
    }

    /**
     * Revoke an OpenPGP key by a private key.
     * Return clone of the key object with the new revocation signature added.
     *
     * @param Type\PrivateKeyInterface $privateKey
     * @param Type\KeyInterface $key
     * @param string $revocationReason
     * @param Enum\RevocationReasonTag $reasonTag
     * @param \DateTimeInterface $time
     * @return Type\KeyInterface
     */
    public static function revokeKey(
        Type\PrivateKeyInterface $privateKey,
        Type\KeyInterface $key,
        string $revocationReason = '',
        ?Enum\RevocationReasonTag $reasonTag = null,
        ?\DateTimeInterface $time = null
    ): Type\KeyInterface
    {
        return $privateKey->revokeKey(
            $key, $revocationReason, $reasonTag, $time
        );
    }

    /**
     * Read OpenPGP signature from armored/binary string.
     * Return a signature object.
     *
     * @param string $signature
     * @param bool $armored
     * @return Type\SignatureInterface
     */
    public static function readSignature(
        string $signature, bool $armored = true
    ): Type\SignatureInterface
    {
        return $armored ?
            Message\Signature::fromArmored($signature) :
            Message\Signature::fromBytes($signature);
    }

    /**
     * Read OpenPGP signed message from armored string.
     * Return a signed message object.
     *
     * @param string $signedMessage
     * @return Type\SignedMessageInterface
     */
    public static function readSignedMessage(
        string $signedMessage
    ): Type\SignedMessageInterface
    {
        return Message\SignedMessage::fromArmored($signedMessage);
    }

    /**
     * Read OpenPGP encrypted message from armored/binary string.
     * Return an encrypted message object.
     *
     * @param string $message
     * @param bool $armored
     * @return Type\EncryptedMessageInterface
     */
    public static function readEncryptedMessage(
        string $message, bool $armored = true
    ): Type\EncryptedMessageInterface
    {
        return $armored ?
            Message\EncryptedMessage::fromArmored($message) :
            Message\EncryptedMessage::fromBytes($message);
    }

    /**
     * Read OpenPGP literal message from armored/binary string.
     * Return a literal message object.
     *
     * @param string $message
     * @param bool $armored
     * @return Type\LiteralMessageInterface
     */
    public static function readLiteralMessage(
        string $message, bool $armored = true
    ): Type\LiteralMessageInterface
    {
        return $armored ?
            Message\LiteralMessage::fromArmored($message) :
            Message\LiteralMessage::fromBytes($message);
    }

    /**
     * Create new cleartext message object from text.
     *
     * @param string $text
     * @return Type\CleartextMessageInterface
     */
    public static function createCleartextMessage(
        string $text
    ): Type\CleartextMessageInterface
    {
        return new Message\CleartextMessage($text);
    }

    /**
     * Create new literal message object from literal data.
     *
     * @param string $literalData
     * @param string $filename
     * @param \DateTimeInterface $time
     * @return Type\LiteralMessageInterface
     */
    public static function createLiteralMessage(
        string $literalData,
        string $filename = '',
        ?\DateTimeInterface $time = null
    ): Type\LiteralMessageInterface
    {
        return Message\LiteralMessage::fromLiteralData(
            $literalData, $filename, $time
        );
    }

    /**
     * Sign a cleartext message.
     * Return a signed message object
     *
     * @param string $text
     * @param array $signingKeys
     * @param Type\NotationDataInterface $notationData
     * @param \DateTimeInterface $time
     * @return Type\SignedMessageInterface
     */
    public static function signCleartext(
        string $text,
        array $signingKeys,
        ?Type\NotationDataInterface $notationData = null,
        ?\DateTimeInterface $time = null
    ): Type\SignedMessageInterface
    {
        return self::createCleartextMessage($text)->sign(
            $signingKeys, $notationData, $time
        );
    }

    /**
     * Sign a cleartext message & return detached signature.
     *
     * @param string $text
     * @param array $signingKeys
     * @param Type\NotationDataInterface $notationData
     * @param \DateTimeInterface $time
     * @return Type\SignatureInterface
     */
    public static function signDetachedCleartext(
        string $text,
        array $signingKeys,
        ?Type\NotationDataInterface $notationData = null,
        ?\DateTimeInterface $time = null
    ): Type\SignatureInterface
    {
        return self::createCleartextMessage($text)->signDetached(
            $signingKeys, $notationData, $time
        );
    }

    /**
     * Sign a message & return signed literal message.
     *
     * @param Type\LiteralMessageInterface $message
     * @param array $signingKeys
     * @param Type\NotationDataInterface $notationData
     * @param \DateTimeInterface $time
     * @return Type\LiteralMessageInterface
     */
    public static function sign(
        Type\LiteralMessageInterface $message,
        array $signingKeys,
        ?Type\NotationDataInterface $notationData = null,
        ?\DateTimeInterface $time = null
    ): Type\LiteralMessageInterface
    {
        return $message->sign(
            $signingKeys, $notationData, $time
        );
    }

    /**
     * Sign a message & return detached signature.
     *
     * @param Type\LiteralMessageInterface $message
     * @param array $signingKeys
     * @param Type\NotationDataInterface $notationData
     * @param \DateTimeInterface $time
     * @return Type\SignatureInterface
     */
    public static function signDetached(
        Type\LiteralMessageInterface $message,
        array $signingKeys,
        ?Type\NotationDataInterface $notationData = null,
        ?\DateTimeInterface $time = null
    ): Type\SignatureInterface
    {
        return $message->signDetached(
            $signingKeys, $notationData, $time
        );
    }

    /**
     * Verify signatures of cleartext signed message.
     * Return verification array.
     *
     * @param string $armoredSignedMessage
     * @param array $verificationKeys
     * @param \DateTimeInterface $time
     * @return array
     */
    public static function verify(
        string $armoredSignedMessage,
        array $verificationKeys,
        ?\DateTimeInterface $time = null
    ): array
    {
        return self::readSignedMessage(
            $armoredSignedMessage
        )->verify($verificationKeys, $time);
    }

    /**
     * Verify detached signatures of cleartext message.
     * Return verification array.
     *
     * @param string $text
     * @param string $signature
     * @param array $verificationKeys
     * @param bool $armored
     * @param \DateTimeInterface $time
     * @return array
     */
    public static function verifyDetached(
        string $text,
        string $signature,
        array $verificationKeys,
        bool $armored = true,
        ?\DateTimeInterface $time = null
    ): array
    {
        return self::createCleartextMessage($text)->verifyDetached(
            $verificationKeys,
            self::readSignature($signature, $armored),
            $time
        );
    }

    /**
     * Encrypt a message using public keys, passwords or both at once.
     * At least one of `encryptionKeys`, `passwords`must be specified.
     * If signing keys are specified, those will be used to sign the message.
     *
     * @param Type\LiteralMessageInterface $message
     * @param array $encryptionKeys
     * @param array $passwords
     * @param array $signingKeys
     * @param Enum\SymmetricAlgorithm $symmetric
     * @param Enum\CompressionAlgorithm $compression
     * @param Type\NotationDataInterface $notationData
     * @param \DateTimeInterface $time
     * @return Type\EncryptedMessageInterface
     */
    public static function encrypt(
        Type\LiteralMessageInterface $message,
        array $encryptionKeys = [],
        array $passwords = [],
        array $signingKeys = [],
        ?Enum\SymmetricAlgorithm $symmetric = null,
        ?Enum\CompressionAlgorithm $compression = null,
        ?Type\NotationDataInterface $notationData = null,
        ?\DateTimeInterface $time = null
    ): Type\EncryptedMessageInterface
    {
        if (!empty($signingKeys)) {
            return $message->sign(
                $signingKeys, $notationData, $time
            )->compress($compression)->encrypt(
                $encryptionKeys, $passwords, $symmetric
            );
        }
        else {
            return $message->compress($compression)->encrypt(
                $encryptionKeys, $passwords, $symmetric
            );
        }
    }

    /**
     * Decrypt a message with the user's private key, or a password.
     * One of `decryptionKeys` or `passwords` must be specified
     *
     * @param Type\EncryptedMessageInterface $message
     * @param array $decryptionKeys
     * @param array $passwords
     * @return Type\LiteralMessageInterface
     */
    public static function decrypt(
        Type\EncryptedMessageInterface $message,
        array $decryptionKeys = [],
        array $passwords = []
    ): Type\LiteralMessageInterface
    {
        return $message->decrypt(
            $decryptionKeys, $passwords
        );
    }
}
