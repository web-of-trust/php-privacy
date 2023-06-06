<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\{
    HashAlgorithm,
    S2kType,
    S2kUsage,
    SymmetricAlgorithm,
};

/**
 * Secret key packet interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SecretKeyPacketInterface extends KeyPacketInterface
{
    /**
     * Get public key packet
     *
     * @return PublicKeyPacketInterface
     */
    function getPublicKey(): PublicKeyPacketInterface;

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
     * Encrypt secret key with passphrase
     *
     * @param string $passphrase
     * @param SymmetricAlgorithm $symmetric
     * @return self
     */
    function encrypt(
        string $passphrase,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self;

    /**
     * Decrypt secret key with passphrase
     *
     * @param string $passphrase
     * @return self
     */
    function decrypt(string $passphrase): self;
}
