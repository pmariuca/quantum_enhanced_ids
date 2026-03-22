import { Component, Input } from '@angular/core';
import { NgClass } from '@angular/common';

@Component({
  selector: 'app-button',
  standalone: true,
  imports: [NgClass],
  templateUrl: './button.component.html',
})
export class ButtonComponent {
  @Input() variant: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link' = 'default';
  @Input() size: 'default' | 'sm' | 'lg' | 'icon' = 'default';
  @Input() className = '';
  @Input() type: 'button' | 'submit' = 'button';

  get classes(): string {
    const base = "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-xl text-sm font-medium transition-all duration-300";

    const variants: Record<string, string> = {
    default: "bg-gradient-to-r from-primary to-secondary text-white shadow-[0_0_30px_rgba(217,70,239,0.5)] hover:shadow-[0_0_50px_rgba(217,70,239,0.7)]",
    destructive: "bg-destructive text-white hover:bg-[#ff006e]/90",
    outline: "border bg-background text-foreground hover:bg-accent",
    secondary: "bg-secondary text-secondary-foreground hover:bg-[#8b5cf6]/80",
    ghost: "hover:bg-accent hover:text-accent-foreground",
    link: "text-primary underline-offset-4 hover:underline",
  };

    const sizes: Record<string, string> = {
      default: "h-9 px-4 py-2",
      sm: "h-8 px-3",
      lg: "h-10 px-6",
      icon: "h-9 w-9",
    };

    return `${base} ${variants[this.variant]} ${sizes[this.size]} ${this.className}`;
  }
}