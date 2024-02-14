import { PartialType, PickType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';
import { ValidateNested } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from 'src/enums/UserRole';

// Using this syntax is way more elegant, and best practice of Typescript & Nestjs
// However, the down side is it will be empty in the swagger
export class UpdateUserDto extends PartialType(
  PickType(CreateUserDto, ['username', 'phone', 'role'] as const),
) {}
