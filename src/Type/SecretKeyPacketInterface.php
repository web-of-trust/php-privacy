<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\{AeadAlgorithm, SymmetricAlgorithm};

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
     * Get secret key material
     *
     * @return SecretKeyMaterialInterface
     */
    function getSecretKeyMaterial(): ?SecretKeyMaterialInterface;

    /**
     * Get public key packet
     *
     * @return PublicKeyPacketInterface
     */
    function getPublicKey(): PublicKeyPacketInterface;

    /**
     * Get AEAD algorithm
     *
     * @return AeadAlgorithm
     */
    function getAead(): ?AeadAlgorithm;

    /**
     * Return secret key packet is encrypted
     *
     * @return bool
     */
    function isEncrypted(): bool;

    /**
     * Return secret key packet is decrypted
     *
     * @return bool
     */
    function isDecrypted(): bool;

    /**
     * Encrypt secret key packet with passphrase
     *
     * @param string $passphrase
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @return self
     */
    function encrypt(
        string $passphrase,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        ?AeadAlgorithm $aead = null,
    ): self;

    /**
     * Decrypt secret key packet with passphrase
     *
     * @param string $passphrase
     * @return self
     */
    function decrypt(string $passphrase): self;
}
