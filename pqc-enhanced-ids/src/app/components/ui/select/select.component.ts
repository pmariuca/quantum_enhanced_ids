import { Component, Input, Output, EventEmitter, ElementRef } from '@angular/core';
import { NgFor, NgIf, NgClass } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';

@Component({
  selector: 'app-select',
  imports: [
    LucideAngularModule,
    NgFor, 
    NgIf,
    NgClass
  ],
  templateUrl: './select.component.html',
  styleUrl: './select.component.css'
})
export class SelectComponent {
  @Input() options: { label: string; value: string }[] = [];
  @Input() value: string = '';
  @Output() valueChange = new EventEmitter<string>();

  constructor(private el: ElementRef) {}

  open = false;
  openUpwards = false;

  toggle() {
    this.open = !this.open;

    if (this.open) {
      setTimeout(() => {
        const rect = this.el.nativeElement.getBoundingClientRect();
        const spaceBelow = window.innerHeight - rect.bottom;

        this.openUpwards = spaceBelow < 150;
      });
    }
  }

  select(value: string) {
    this.value = value;
    this.valueChange.emit(value);
    this.open = false;
  }

  get selectedLabel() {
    return this.options.find(o => o.value === this.value)?.label || 'Select...';
  }
}
