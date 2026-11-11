// ============================================================================
// CATHY'S ANGULAR 21 PORTFOLIO — CLASS 2 (October 22, 2026)
// Topic: Two-Way Data Binding [(ngModel)] ("Banana in a Box"), FormsModule,
//        Input Text Boxes, and Multiple Buttons/Methods (Add & Multiply)
// ============================================================================

import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-root',
  imports: [FormsModule],
  template: `
    <h1>Hello, {{ name }}!!</h1>

    <p>Enter Number 1: <input type="number" [(ngModel)]="num1"></p>
    <p>Enter Number 2: <input type="number" [(ngModel)]="num2"></p>

    <button (click)="Multiply2numbers()">Multiply2numbers!</button>
    <button (click)="Add2numbers()">Add2numbers!</button>

    <h2>Total = {{ total }}</h2>
  `
})
export class App {
  name = 'Cathy the Angular Pro';
  num1 = 0;
  num2 = 0;
  total = 0;

  Multiply2numbers() {
    this.total = this.num1 * this.num2;
  }

  Add2numbers() {
    this.total = this.num1 + this.num2;
  }
}
