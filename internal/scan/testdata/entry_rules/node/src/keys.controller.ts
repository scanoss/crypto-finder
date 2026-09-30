import { Controller, Post } from '@nestjs/common';
import { createHash } from 'crypto';

@Controller('keys')
export class KeysController {
  @Post('rotate')
  rotate(): string {
    return createHash('sha512').update('rotate').digest('hex');
  }
}
