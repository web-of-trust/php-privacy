<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;
use OpenPGP\Enum\{CurveOid, KeyAlgorithm, RevocationReasonTag, RSAKeySize};

/**
 * Private key interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface PrivateKeyInterface extends KeyInterface
{
    /**
     * Return true if the key packet is encrypted.
     *
     * @return bool
     */
    function isEncrypted(): bool;

    /**
     * Return true if the key packet is decrypted.
     *
     * @return bool
     */
    function isDecrypted(): bool;

    /**
     * Return true if the key packet is aead protected.
     *
     * @return bool
     */
    function aeadProtected(): bool;

    /**
     * Get secret key packet.
     *
     * @return SecretKeyPacketInterface
     */
    function getSecretKeyPacket(): SecretKeyPacketInterface;

    /**
     * Get array of key packets that is available for decryption
     *
     * @param string $keyID
     * @param DateTimeInterface $time
     * @return array
     */
    function getDecryptionKeyPackets(
        string $keyID = "",
        ?DateTimeInterface $time = null
    ): array;

    /**
     * Lock a private key with the given passphrase.
     * This method does not change the original key.
     *
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @return self
     */
    function encrypt(string $passphrase, array $subkeyPassphrases = []): self;

    /**
     * Unlock a private key with the given passphrase.
     * This method does not change the original key.
     *
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @return self
     */
    function decrypt(string $passphrase, array $subkeyPassphrases = []): self;

    /**
     * Add userIDs to the key.
     * Return a clone of the key object with the new userIDs added.
     *
     * @param array $userIDs
     * @return self
     */
    function addUsers(array $userIDs): self;

    /**
     * Generate a new OpenPGP subkey
     * Return a clone of the key object with the new subkey added.
     *
     * @param string $passphrase
     * @param KeyAlgorithm $keyAlgorithm
     * @param RSAKeySize $rsaKeySize
     * @param CurveOid $curve
     * @param int $keyExpiry
     * @param bool $forSigning
     * @param DateTimeInterface $time
     * @return self
     */
    function addSubkey(
        string $passphrase,
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::Normal,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        bool $forSigning = false,
        ?DateTimeInterface $time = null
    ): self;

    /**
     * Certify an OpenPGP key.
     * Return clone of the key object with the new certification added.
     *
     * @param KeyInterface $key
     * @param DateTimeInterface $time
     * @return KeyInterface
     */
    function certifyKey(
        KeyInterface $key,
        ?DateTimeInterface $time = null
    ): KeyInterface;

    /**
     * Revoke an OpenPGP key.
     * Return clone of the key object with the new revocation signature added.
     *
     * @param KeyInterface $key
     * @param string $revocationReason
     * @param DateTimeInterface $time
     * @param RevocationReasonTag $reasonTag
     * @return KeyInterface
     */
    function revokeKey(
        KeyInterface $key,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): KeyInterface;

    /**
     * Revoke user & return a clone of the key object with the new revoked user.
     *
     * @param string $userID
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return self
     */
    function revokeUser(
        string $userID,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): self;

    /**
     * Revoke subkey & return a clone of the key object with the new revoked subkey.
     *
     * @param string $keyID
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return self
     */
    function revokeSubkey(
        string $keyID,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): self;
}
