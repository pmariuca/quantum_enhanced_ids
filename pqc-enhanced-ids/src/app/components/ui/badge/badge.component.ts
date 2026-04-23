import { Component, Input } from '@angular/core';
import { NgClass } from '@angular/common';

@Component({
  selector: 'app-badge',
  imports: [NgClass],
  templateUrl: './badge.component.html',
  styleUrl: './badge.component.css'
})
export class BadgeComponent {
  @Input() variant: 'default' | 'secondary' | 'destructive' | 'outline' = 'default';
  @Input() className = '';

  get classes(): string {
    const base =
      "inline-flex items-center justify-center rounded-md border border-transparent px-2 py-0.5 text-xs font-medium w-fit whitespace-nowrap shrink-0 gap-1 transition-all";

    const variants: Record<string, string> = {
      default: "border-transparent bg-primary text-primary-foreground",
      secondary: "border-transparent bg-secondary text-secondary-foreground",
      destructive: "border-transparent bg-destructive text-white",
      outline: "text-foreground border border-border",
    };

    const variantClass = this.className ? '' : variants[this.variant];
    return `${base} ${variantClass} ${this.className}`.trim();
  }
}
