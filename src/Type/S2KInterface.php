<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

/**
 * String-to-key interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface S2KInterface
{
    /**
     * Produce a key using the specified passphrase and the defined hash algorithm
     * 
     * @param string $passphrase
     * @param int $keyLen
     * @return string
     */
    function produceKey(string $passphrase, int $keyLen): string;
}
