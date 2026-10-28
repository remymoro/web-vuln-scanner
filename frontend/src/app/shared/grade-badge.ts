import { Component, input } from '@angular/core';
import { Grade } from '../core/api.models';

@Component({
  selector: 'app-grade-badge',
  styles: ':host { display: inline-block; }',
  template: `<span
    class="grade"
    [class]="'grade grade-' + grade()"
    [attr.aria-label]="'Note ' + grade()"
    >{{ grade() }}</span
  >`,
})
export class GradeBadge {
  readonly grade = input.required<Grade>();
}
