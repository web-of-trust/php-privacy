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

/**
 * SignedMessage class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SignedMessage extends CleartextMessage implements ArmorableInterface, SignedMessageInterface
{
    /**
     * Constructor
     *
     * @param string $text
     * @param Signature $signature
     * @param array $verifications
     * @return self
     */
    public function __construct(
        string $text,
        private readonly Signature $signature,
        private readonly array $verifications = [],
    )
    {
        parent::__construct($text);
    }

    public function getSignature(): Signature
    {
        return $this->signature;
    }

    public function getVerifications(): array
    {
        return $this->verifications;
    }
}
