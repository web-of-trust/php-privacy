<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Symmetric;

use phpseclib3\Crypt\Common\BlockCipher;

/**
 * CamelliaLight class
 *
 * @package    OpenPGP
 * @category   Cryptor
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
class CamelliaLight extends BlockCipher
{
    const BLOCK_SIZE = 16;

    /**
     * Constructor
     *
     * @param string $mode
     * @return self
     */
    public function __construct(string $mode)
    {
        parent::__construct($mode);
        $this->block_size = self::BLOCK_SIZE;
        if ($this->mode == self::MODE_STREAM) {
            throw new BadModeException('Block ciphers cannot be ran in stream mode');
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function encryptBlock($input)
    {
    }

    /**
     * {@inheritdoc}
     */
    protected function decryptBlock($input)
    {
    }

    /**
     * {@inheritdoc}
     */
    protected function setupKey()
    {
    }
}
