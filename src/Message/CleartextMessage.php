<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use \DateTime;
use OpenPGP\Type\MessageInterface;

/**
 * Cleartext message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class CleartextMessage implements MessageInterface
{
    /**
     * Constructor
     *
     * @param string $text
     * @return self
     */
    public function __construct(
        private readonly string $text
    )
    {
    }

    /**
     * Gets cleartext
     *
     * @return string
     */
    public function getText(): string
    {
        return $this->text;
    }

    /**
     * Gets normalized cleartext
     *
     * @return string
     */
    public function getNormalizeText(): string
    {
        return preg_replace('/\r\n/im', "\n", $this->text);
    }

    public function sign(array $signingKeys, ?DateTime $time): SignedMessageInterface
    {
    }

    public function signDetached(array $signingKeys, ?DateTime $time): SignatureInterface
    {
    }
}
