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
 * Ocb block cipher mode class
 *
 * @package    OpenPGP
 * @category   Cryptor
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
class OcbMode extends BlockCipher
{
    /**
     * Constructor
     *
     * @param BlockCipher $underlyingCipher
     * @return self
     */
    public function __construct(
        private readonly BlockCipher $underlyingCipher
    )
    {
    }
}
