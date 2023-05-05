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

use DateTime;

/**
 * Message interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface MessageInterface extends ArmorableInterface
{
    /**
     * Sign the message
     *
     * @param array $signingKeys
     * @param DateTime $date
     * @return MessageInterface
     */
	function sign(array $signingKeys, ?DateTime $date = NULL): MessageInterface;

    /**
     * Verify signatures of signed message
     *
     * @param array $verificationKeys
     * @param DateTime $date
     * @return MessageInterface
     */
	function verify(array $verificationKeys, ?DateTime $date = NULL): MessageInterface;
}
