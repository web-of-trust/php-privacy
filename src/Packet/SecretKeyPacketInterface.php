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
    HashAlgorithm, S2kType, S2kUsage, SymmetricAlgorithm
};

/**
 * Secret key packet interface
 * 
 * @package   OpenPGP
 * @category  Packet
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
     * Encrypts secret key with passphrase
     *
     * @param string $passphrase
     * @param S2kUsage $s2kUsage
     * @param SymmetricAlgorithm $symmetric
     * @param HashAlgorithm $symmetric
     * @param HashAlgorithm $hash
     * @param S2kType $s2kType
     * @return SecretKeyPacketInterface
     */
    function encrypt(
        string $passphrase,
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        HashAlgorithm $hash = HashAlgorithm::Sha1,
        S2kType $s2kType = S2kType::Iterated
    ): SecretKeyPacketInterface;

    /**
     * Decrypts secret key with passphrase
     *
     * @param string $passphrase
     * @return SecretKeyPacketInterface
     */
    function decrypt(string $passphrase): SecretKeyPacketInterface;
}
