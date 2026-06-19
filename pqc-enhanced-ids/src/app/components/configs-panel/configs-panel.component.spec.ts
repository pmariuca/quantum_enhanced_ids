import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConfigsPanelComponent } from './configs-panel.component';

describe('ConfigsPanelComponent', () => {
  let component: ConfigsPanelComponent;
  let fixture: ComponentFixture<ConfigsPanelComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ConfigsPanelComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ConfigsPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
