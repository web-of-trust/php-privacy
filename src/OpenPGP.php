<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP;

use DateTime;
use OpenPGP\Enum\{
    CompressionAlgorithm,
    CurveOid,
    DHKeySize,
    KeyType,
    RSAKeySize,
    SymmetricAlgorithm,
};
use OpenPGP\Key\{
    PrivateKey,
    PublicKey,
};
use OpenPGP\Message\{
    CleartextMessage,
    Signature,
    LiteralMessage,
    SignedMessage,
};
use OpenPGP\Type\{
    CleartextMessageInterface,
    EncryptedMessageInterface,
    LiteralMessageInterface,
    SignatureInterface,
    SignedMessageInterface,
};

/**
 * OpenPGP class
 *
 * @package   OpenPGP
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
final class OpenPGP
{
    /**
     * Generates a new OpenPGP key pair. Supports RSA, DSA and ECC key types.
     * By default, primary and subkeys will be of same type.
     * The generated primary key will have signing capabilities.
     * By default, one subkey with encryption capabilities is also generated.
     *
     * @param array<string> $userIDs
     * @param string $passphrase
     * @param KeyType $type
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curve
     * @param int $keyExpiry
     * @param DateTime $time
     * @return PrivateKey
     */
    public static function generateKey(
        array $userIDs,
        string $passphrase,
        KeyType $type = KeyType::Rsa,
        RSAKeySize $rsaKeySize = RSAKeySize::S4096,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        ?DateTime $time = null
    ): PrivateKey
    {
        return PrivateKey::generate(
            $userIDs,
            $passphrase,
            $type,
            $rsaKeySize,
            $dhKeySize,
            $curve,
            $keyExpiry,
            $time
        );
    }

    /**
     * Read an armored & unlock OpenPGP private key with the given passphrase.
     *
     * @param string $armoredPrivateKey
     * @param string $passphrase
     * @param array<string> $subkeyPassphrases
     * @return PrivateKey
     */
    public static function decryptPrivateKey(
        string $armoredPrivateKey,
        string $passphrase,
        array $subkeyPassphrases = []
    ): PrivateKey
    {
        return self::readPrivateKey($armoredPrivateKey)->decrypt(
            $passphrase, $subkeyPassphrases
        );
    }

    /**
     * Read an armored OpenPGP private key and returns a PrivateKey object
     *
     * @param string $armoredPrivateKey
     * @return PrivateKey
     */
    public static function readPrivateKey(
        string $armoredPrivateKey
    ): PrivateKey
    {
        return PrivateKey::fromArmored($armoredPrivateKey);
    }

    /**
     * Read an armored OpenPGP public key and returns a PublicKey object
     *
     * @param string $armoredPublicKey
     * @return PublicKey
     */
    public static function readPublicKey(
        string $armoredPublicKey
    ): PublicKey
    {
        return PublicKey::fromArmored($armoredPublicKey);
    }

    /**
     * Read an armored OpenPGP signature and returns a Signature object
     *
     * @param string $armoredSignature
     * @return Signature
     */
    public static function readSignature(
        string $armoredSignature
    ): Signature
    {
        return Signature::fromArmored($armoredSignature);
    }

    /**
     * Read an armored OpenPGP signed message and returns a SignedMessage object
     *
     * @param string $armoredSignedMessage
     * @return SignedMessage
     */
    public static function readSignedMessage(
        string $armoredSignedMessage
    ): SignedMessage
    {
        return SignedMessage::fromArmored($armoredSignedMessage);
    }

    /**
     * Read an armored OpenPGP message and returns a LiteralMessage object
     *
     * @param string $armoredMessage
     * @return LiteralMessageInterface
     */
    public static function readLiteralMessage(
        string $armoredMessage
    ): LiteralMessageInterface
    {
        return LiteralMessage::fromArmored($armoredMessage);
    }

    /**
     * Create new cleartext message object from text
     *
     * @param string $text
     * @return CleartextMessageInterface
     */
    public static function createCleartextMessage(
        string $text
    ): CleartextMessageInterface
    {
        return new CleartextMessage($text);
    }

    /**
     * Create new literal message object from literal data.
     *
     * @param string $literalData
     * @param string $filename
     * @param DateTime $time
     * @return LiteralMessage
     */
    public static function createLiteralMessage(
        string $literalData,
        string $filename = '',
        ?DateTime $time = null
    ): LiteralMessage
    {
        return LiteralMessage::fromLiteralData(
            $literalData, $filename, $time
        );
    }

    /**
     * Sign a cleartext message.
     *
     * @param string $text
     * @param array<PrivateKey> $signingKeys
     * @param DateTime $time
     * @return SignedMessageInterface
     */
    public static function signCleartext(
        string $text,
        array $signingKeys,
        ?DateTime $time = null
    ): SignedMessageInterface
    {
        return self::createCleartextMessage($text)->sign(
            $signingKeys, $time
        );
    }

    /**
     * Sign a cleartext message & return detached signature
     *
     * @param string $text
     * @param array<PrivateKey> $signingKeys
     * @param DateTime $time
     * @return SignatureInterface
     */
    public static function signDetachedCleartext(
        string $text,
        array $signingKeys,
        ?DateTime $time = null
    ): SignatureInterface
    {
        return self::createCleartextMessage($text)->signDetached(
            $signingKeys, $time
        );
    }

    /**
     * Sign a message & return signed message
     *
     * @param LiteralMessageInterface $message
     * @param array<Key\PrivateKey> $signingKeys
     * @param DateTime $time
     * @return LiteralMessageInterface
     */
    public static function sign(
        LiteralMessageInterface $message,
        array $signingKeys,
        ?DateTime $time = null
    ): LiteralMessageInterface
    {
        return $message->sign(
            $signingKeys, $time
        );
    }

    /**
     * Sign a message & return detached signature
     *
     * @param LiteralMessageInterface $message
     * @param array<Key\PrivateKey> $signingKeys
     * @param DateTime $time
     * @return SignatureInterface
     */
    public static function signDetached(
        LiteralMessageInterface $message,
        array $signingKeys,
        ?DateTime $time = null
    ): SignatureInterface
    {
        return $message->signDetached(
            $signingKeys, $time
        );
    }

    /**
     * Verify signatures of cleartext signed message
     * Return verification array
     *
     * @param string $armoredSignedMessage
     * @param array<PublicKey> $verificationKeys
     * @param DateTime $time
     * @return array<Type\VerificationInterface>
     */
    public static function verify(
        string $armoredSignedMessage,
        array $verificationKeys,
        ?DateTime $time = null
    ): array
    {
        return self::readSignedMessage($armoredSignedMessage)
            ->verify($verificationKeys, $time);
    }

    /**
     * Verify detached signatures of cleartext message
     * Return verification array
     *
     * @param string $text
     * @param string $armoredSignature
     * @param array<Key\PublicKey> $verificationKeys
     * @param DateTime $time
     * @return array<Type\VerificationInterface>
     */
    public static function verifyDetached(
        string $text,
        string $armoredSignature,
        array $verificationKeys,
        ?DateTime $time = null
    ): array
    {
        return self::createCleartextMessage($text)->verifyDetached(
            $verificationKeys, self::readSignature($armoredSignature), $time
        );
    }

    /**
     * Encrypt a message using public keys, passwords or both at once.
     * At least one of `encryptionKeys`, `passwords`must be specified.
     * If signing keys are specified, those will be used to sign the message.
     *
     * @param LiteralMessageInterface $message
     * @param array<Key\PublicKey> $encryptionKeys
     * @param array<string> $passwords
     * @param array<Key\PrivateKey> $signingKeys
     * @param SymmetricAlgorithm $symmetric
     * @param CompressionAlgorithm $compression
     * @param DateTime $time
     * @return EncryptedMessageInterface
     */
    public static function encrypt(
        LiteralMessageInterface $message,
        array $encryptionKeys = [],
        array $passwords = [],
        array $signingKeys = [],
        ?SymmetricAlgorithm $symmetric = null,
        ?CompressionAlgorithm $compression = null,
        ?DateTime $time = null
    ): EncryptedMessageInterface
    {
        if (!empty($signingKeys)) {
            return $message->sign($signingKeys, $time)
                ->compress($compression)
                ->encrypt($encryptionKeys, $passwords, $symmetric);
        }
        else {
            return $message->compress($compression)
                ->encrypt($encryptionKeys, $passwords, $symmetric);
        }
    }

    /**
     * Decrypt a message with the user's private key, or a password.
     * One of `decryptionKeys` or `passwords` must be specified
     *
     * @param EncryptedMessageInterface $message
     * @param array<Key\PrivateKey> $decryptionKeys
     * @param array<string> $passwords
     * @return LiteralMessageInterface
     */
    public static function decrypt(
        EncryptedMessageInterface $message,
        array $decryptionKeys = [],
        array $passwords = []
    ): LiteralMessageInterface
    {
        return $message->decrypt(
            $decryptionKeys, $passwords
        );
    }
}
