import { Injectable, NotFoundException } from '@nestjs/common';
import { DeepPartial, FindOptionsSelect } from 'typeorm';
import { UserRepository } from './user.repository';
import { User } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { convertArrayToObject } from 'src/shared/utils/utils';

@Injectable()
export class UserService {
  constructor(private userRepository: UserRepository) {}

  async getAllUsers(): Promise<User[]> {
    return this.userRepository.find();
  }

  async getUserById(
    id: number,
    select?: FindOptionsSelect<User>,
  ): Promise<User> {
    const user = await this.userRepository.findById(id, select);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findUsersWithProjection(keys: string[]): Promise<Partial<User>[]> {
    const queryBuilder = this.userRepository.createQueryBuilder('user');
    keys.forEach((key) => {
      queryBuilder.addSelect(`user.${key}`);
    });
    return queryBuilder.getMany();
  } 

  async createUser(createUserDto: CreateUserDto): Promise<User> {
    const user = this.userRepository.create({
      username: createUserDto.username,
      phone: createUserDto.phone,
      role: createUserDto.role,
      email: createUserDto.email,
      password: createUserDto.password,
      emailVerified: false,
    });
    return this.userRepository.save(user);
  }

  async updateUser(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.getUserById(id);

    const updateData: DeepPartial<User> = {
      username: updateUserDto.username,
      phone: updateUserDto.phone,
      role: updateUserDto.role,
    };

    this.userRepository.merge(user, updateData);
    return this.userRepository.save(user);
  }

  async deleteUser(id: number): Promise<void> {
    const user = await this.getUserById(id);
    await this.userRepository.remove(user);
  }

  async findAllDropdownData(fields: string[]): Promise<User[]> {
    const select = convertArrayToObject(fields);
    return await this.userRepository.find({
      select,
    });
  }

  async getUserByEmail(email: string, checkForExists: boolean = true) {
    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'emailVerified'],
    });
    if (!user && checkForExists) {
      throw new NotFoundException('User not found');
    }
    return user as User;
  }

  async verifyUser(email: string) {
    const user = await this.getUserByEmail(email);

    const updateData: DeepPartial<User> = {
      emailVerified: true,
    };

    this.userRepository.merge(user, updateData);
    return this.userRepository.save(user);
  }

  async changePassword(email: string, password: string) {
    const user = await this.getUserByEmail(email);
    const updateData: DeepPartial<User> = {
      password,
    };

    this.userRepository.merge(user, updateData);
    return this.userRepository.save(user);
  }
}
