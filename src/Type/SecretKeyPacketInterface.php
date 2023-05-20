<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\{
    HashAlgorithm, S2kType, S2kUsage, SymmetricAlgorithm
};

/**
 * Secret key packet interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SecretKeyPacketInterface extends KeyPacketInterface
{
    /**
     * Gets public key packet
     *
     * @return KeyPacketInterface
     */
    function getPublicKey(): KeyPacketInterface;

    /**
     * Return secret key packed is encrypted
     *
     * @return bool
     */
    function isEncrypted(): bool;

    /**
     * Return secret key packed is decrypted
     *
     * @return bool
     */
    function isDecrypted(): bool;

    /**
     * Encrypts secret key with passphrase
     *
     * @param string $passphrase
     * @param S2kUsage $s2kUsage
     * @param SymmetricAlgorithm $symmetric
     * @param HashAlgorithm $symmetric
     * @param HashAlgorithm $hash
     * @param S2kType $s2kType
     * @return self
     */
    function encrypt(
        string $passphrase,
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        HashAlgorithm $hash = HashAlgorithm::Sha1,
        S2kType $s2kType = S2kType::Iterated
    ): self;

    /**
     * Decrypts secret key with passphrase
     *
     * @param string $self
     * @return SecretKeyPacketInterface
     */
    function decrypt(string $passphrase): self;
}
