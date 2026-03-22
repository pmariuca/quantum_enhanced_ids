import { Component, Input } from '@angular/core';
import { NgClass } from '@angular/common';

@Component({
  selector: 'app-scroll-area',
  imports: [NgClass],
  templateUrl: './scroll-area.component.html',
  styleUrl: './scroll-area.component.css'
})
export class ScrollAreaComponent {
  @Input() className = '';
}
