import {
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  registerDecorator,
} from 'class-validator';

@ValidatorConstraint({ name: 'isTimeFormat', async: false })
class IsTimeFormatConstraint implements ValidatorConstraintInterface {
  validate(time: string) {
    // Regular expression to match HH:mm format (24-hour clock)
    const regex = /^([01]\d|2[0-3]):([0-5]\d)$/; // Matches HH:mm format
    return regex.test(time);
  }

  defaultMessage() {
    return 'Invalid time format. Please use HH:mm (24-hour) format.';
  }
}

export function IsTimeFormat(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsTimeFormatConstraint,
    });
  };
}
