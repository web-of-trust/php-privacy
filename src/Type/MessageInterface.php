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

/**
 * Message interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface MessageInterface
{
    /**
     * Sign the message
     *
     * @param array $signingKeys
     * @param int $time
     * @return MessageInterface
     */
	function sign(array $signingKeys, int $time = 0): MessageInterface;

    /**
     * Verify signatures of signed message
     *
     * @param array $verificationKeys
     * @param int $time
     * @return MessageInterface
     */
	function verify(array $verificationKeys, int $time = 0): MessageInterface;
}
