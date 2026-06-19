import { ComponentFixture, TestBed } from '@angular/core/testing';

import { QmlModelPanelComponent } from './qml-model-panel.component';

describe('QmlModelPanelComponent', () => {
  let component: QmlModelPanelComponent;
  let fixture: ComponentFixture<QmlModelPanelComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [QmlModelPanelComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(QmlModelPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
