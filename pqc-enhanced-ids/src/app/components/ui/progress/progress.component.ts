import { Component, Input } from '@angular/core';
import { NgStyle, NgClass } from '@angular/common';

@Component({
  selector: 'app-progress',
  imports: [NgStyle, NgClass],
  templateUrl: './progress.component.html',
})
export class ProgressComponent {
  @Input() value: number = 0;
  @Input() className = '';

  get transform(): string {
    return `translateX(-${100 - this.value}%)`;
  }
}