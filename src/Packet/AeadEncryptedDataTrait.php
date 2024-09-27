<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{AeadAlgorithm, SymmetricAlgorithm};

/**
 * Aead encrypted data packet trait
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
trait AeadEncryptedDataTrait
{
    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * {@inheritdoc}
     */
    public function getSymmetric(): SymmetricAlgorithm
    {
        return $this->symmetric;
    }

    /**
     * {@inheritdoc}
     */
    public function getAead(): ?AeadAlgorithm
    {
        return $this->aead;
    }

    /**
     * {@inheritdoc}
     */
    public function getChunkSize(): int
    {
        return $this->chunkSize;
    }

    /**
     * Get associated data
     *
     * @param int $tag
     * @return string
     */
    private function getAData(int $tag): string
    {
        return implode([
            chr(0xc0 | $tag),
            chr($this->version),
            chr($this->symmetric->value),
            chr($this->aead->value),
            chr($this->chunkSize),
        ]);
    }
}
