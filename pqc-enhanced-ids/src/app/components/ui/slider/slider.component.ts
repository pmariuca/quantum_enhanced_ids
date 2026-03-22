import { Component, Input, Output, EventEmitter } from '@angular/core';
import { NgStyle } from '@angular/common';

@Component({
  selector: 'app-slider',
  imports: [NgStyle],
  templateUrl: './slider.component.html',
})
export class SliderComponent {
  @Input() value: number = 50;
  @Input() min: number = 0;
  @Input() max: number = 100;

  @Output() valueChange = new EventEmitter<number>();

  onChange(event: Event) {
    const val = Number((event.target as HTMLInputElement).value);
    this.value = val;
    this.valueChange.emit(val);
  }

  get percentage(): number {
    return ((this.value - this.min) / (this.max - this.min)) * 100;
  }
}