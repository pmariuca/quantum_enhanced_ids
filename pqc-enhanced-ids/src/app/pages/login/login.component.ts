import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule } from 'lucide-angular';
import { ButtonComponent } from '../../components/ui/button/button.component';
import { LabelComponent } from '../../components/ui/label/label.component';

@Component({
  selector: 'app-login',
  imports: [
    FormsModule,
    LucideAngularModule,
    ButtonComponent,
    LabelComponent
],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent {
  username = '';
  password = '';

  constructor(private router: Router) {}

  handleLogin(event: Event) {
    event.preventDefault();

    if (this.username && this.password) {
      this.router.navigate(['/dashboard']);
    }
  }
}
